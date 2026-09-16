package main

/*
#include <stdlib.h>
#include <stdint.h>
*/
import "C"

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/vmihailenco/msgpack/v5"
	"google.golang.org/protobuf/proto"
	"runtime"
	"runtime/cgo"
	"unsafe"
)

type batchImage struct {
	Name     string          `json:"name"`
	Metadata json.RawMessage `json:"metadata"`
	Extras   json.RawMessage `json:"extras"`
	Sources  []sourceRecord  `json:"sources"`
	Start    int             `json:"start"`
	Count    int             `json:"count"`
	Error    string          `json:"error"`
}
type batchHeader struct {
	Images   []batchImage         `json:"images"`
	Packages []models.PackageInfo `json:"packages"`
	Contexts []denseContext       `json:"contexts"`
	Rows     []byte               `json:"rows"`
	Refs     []byte               `json:"refs"`
	Bodies   []byte               `json:"bodies"`
}
type batchBuilder struct {
	header       batchHeader
	packages     map[models.PackageInfo]int
	contexts     map[string]int
	fingerprints map[[32]byte][]int
	chunks       []*directCWriter
	share        bool
	protobuf     bool
}

func appendU32(out []byte, values ...int) []byte {
	for _, v := range values {
		out = binary.LittleEndian.AppendUint32(out, uint32(v))
	}
	return out
}
func (b *batchBuilder) body(index int) []byte {
	row := b.header.Bodies[index*12:]
	chunk := binary.LittleEndian.Uint32(row)
	off := binary.LittleEndian.Uint32(row[4:])
	n := binary.LittleEndian.Uint32(row[8:])
	return unsafe.Slice((*byte)(unsafe.Add(b.chunks[chunk].p, int(off))), int(n))
}
func (b *batchBuilder) internBody(raw []byte) int {
	hash := sha256.Sum256(raw)
	if b.share {
		for _, index := range b.fingerprints[hash] {
			if bytes.Equal(raw, b.body(index)) {
				return index
			}
		}
	}
	if len(b.chunks) == 0 || b.chunks[len(b.chunks)-1].n+len(raw) > 1024*1024 {
		if len(b.chunks) > 0 {
			b.chunks[len(b.chunks)-1].finish()
		}
		b.chunks = append(b.chunks, &directCWriter{})
	}
	ci := len(b.chunks) - 1
	chunk := b.chunks[ci]
	off := chunk.n
	if _, err := chunk.Write(raw); err != nil {
		panic(err)
	}
	index := len(b.header.Bodies) / 12
	b.header.Bodies = appendU32(b.header.Bodies, ci, off, len(raw))
	if b.share {
		b.fingerprints[hash] = append(b.fingerprints[hash], index)
	}
	return index
}

//export batch_begin
func batch_begin(share C.int, protobuf C.int) C.uintptr_t {
	fastEquality = true
	canonicalBodies = true
	b := &batchBuilder{packages: map[models.PackageInfo]int{}, contexts: map[string]int{}, fingerprints: map[[32]byte][]int{}, share: share != 0, protobuf: protobuf != 0}
	b.header = batchHeader{Images: []batchImage{}, Packages: []models.PackageInfo{}, Contexts: []denseContext{}, Rows: []byte{}, Refs: []byte{}, Bodies: []byte{}}
	return C.uintptr_t(cgo.NewHandle(b))
}

//export batch_add
func batch_add(id C.uintptr_t) {
	b := cgo.Handle(id).Value().(*batchBuilder)
	s := normalizeNative()
	image := batchImage{Name: s.Meta.Image, Metadata: s.Meta.Metadata, Extras: s.Meta.Extras, Sources: s.Meta.Sources, Start: len(b.header.Rows) / 24, Count: len(s.Meta.Occurrences)}
	ii := len(b.header.Images)
	b.header.Images = append(b.header.Images, image)
	pm := make([]int, len(s.Meta.Packages))
	for i, p := range s.Meta.Packages {
		index, ok := b.packages[p]
		if !ok || !b.share {
			index = len(b.header.Packages)
			b.header.Packages = append(b.header.Packages, p)
			if b.share {
				b.packages[p] = index
			}
		}
		pm[i] = index
	}
	am := make([]int, len(s.Advisories))
	var scratch bytes.Buffer
	var protoScratch []byte
	for i, a := range s.Advisories {
		var raw []byte
		if b.protobuf {
			var err error
			protoScratch, err = (proto.MarshalOptions{Deterministic: true}).MarshalAppend(protoScratch[:0], a)
			if err != nil {
				panic(err)
			}
			raw = protoScratch
		} else {
			scratch.Reset()
			if err := encoder(&scratch).Encode(packProto{a}); err != nil {
				panic(err)
			}
			raw = scratch.Bytes()
		}
		am[i] = b.internBody(raw)
	}
	localContexts := map[string]int{}
	for _, o := range s.Meta.Occurrences {
		ctx := denseContext{o.ImageOrigin, o.DepGroups, o.Groups, o.Licenses, o.Violations}
		scratch.Reset()
		e := encoder(&scratch)
		e.SetSortMapKeys(true)
		if err := e.Encode(ctx); err != nil {
			panic(err)
		}
		index, ok := b.contexts[scratch.String()]
		if !b.share {
			index, ok = localContexts[scratch.String()]
		}
		if !ok {
			index = len(b.header.Contexts)
			b.header.Contexts = append(b.header.Contexts, ctx)
			if b.share {
				b.contexts[scratch.String()] = index
			} else {
				localContexts[scratch.String()] = index
			}
		}
		start := len(b.header.Refs) / 4
		for _, a := range o.Advisories {
			b.header.Refs = appendU32(b.header.Refs, am[a])
		}
		b.header.Rows = appendU32(b.header.Rows, ii, o.Source, pm[o.Package], index, start, len(o.Advisories))
	}
	// The batch retains no upstream image/advisory graph.
	value = envelope{}
}

//export batch_add_error
func batch_add_error(id C.uintptr_t) {
	b := cgo.Handle(id).Value().(*batchBuilder)
	b.header.Images = append(b.header.Images, batchImage{Name: "failed-image", Error: "fixture acquisition failure", Start: len(b.header.Rows) / 24})
}

//export batch_header
func batch_header(id C.uintptr_t, out *unsafe.Pointer, n *C.size_t) {
	b := cgo.Handle(id).Value().(*batchBuilder)
	if len(b.chunks) > 0 {
		b.chunks[len(b.chunks)-1].finish()
	}
	w := &directCWriter{}
	e := msgpack.NewEncoder(w)
	e.SetCustomStructTag("json")
	if err := e.Encode(b.header); err != nil {
		panic(err)
	}
	w.finish()
	*out = w.p
	*n = C.size_t(w.n)
}

//export batch_chunk_count
func batch_chunk_count(id C.uintptr_t) C.size_t {
	return C.size_t(len(cgo.Handle(id).Value().(*batchBuilder).chunks))
}

//export batch_take_chunk
func batch_take_chunk(id C.uintptr_t, index C.int, out *unsafe.Pointer, n *C.size_t) {
	w := cgo.Handle(id).Value().(*batchBuilder).chunks[int(index)]
	*out = w.p
	*n = C.size_t(w.n)
	w.p = nil
}

//export batch_c_bytes
func batch_c_bytes(id C.uintptr_t) C.size_t {
	total := 0
	for _, w := range cgo.Handle(id).Value().(*batchBuilder).chunks {
		total += w.capacity
	}
	return C.size_t(total)
}

//export batch_release
func batch_release(id C.uintptr_t) {
	h := cgo.Handle(id)
	b := h.Value().(*batchBuilder)
	for _, w := range b.chunks {
		if w.p != nil {
			C.free(w.p)
			w.p = nil
		}
	}
	h.Delete()
	runtime.GC()
}
