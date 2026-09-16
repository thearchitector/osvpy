package main

/*
#include <stdlib.h>
#include <stdint.h>
typedef void (*dense_sink)(const void*, size_t, int);
static void dense_deliver(dense_sink sink, const void *p, size_t n, int kind) { sink(p, n, kind); }
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/vmihailenco/msgpack/v5"
	"google.golang.org/protobuf/proto"
	"runtime/cgo"
	"unsafe"
)

type denseContext struct {
	ImageOrigin *models.ImageOriginDetails `json:"image_origin_details,omitempty"`
	DepGroups   []string                   `json:"dependency_groups,omitempty"`
	Groups      []models.GroupInfo         `json:"groups,omitempty"`
	Licenses    []models.License           `json:"licenses,omitempty"`
	Violations  []models.License           `json:"license_violations,omitempty"`
}
type denseMeta struct {
	Image       string               `json:"image"`
	Metadata    json.RawMessage      `json:"metadata"`
	Sources     []sourceRecord       `json:"sources"`
	Packages    []models.PackageInfo `json:"packages"`
	Contexts    []denseContext       `json:"contexts"`
	Occurrences []byte               `json:"occurrences"`
	Refs        []byte               `json:"refs"`
	Extras      json.RawMessage      `json:"extras"`
}

func denseProjection(s *normalizedStore) denseMeta {
	m := denseMeta{Image: s.Meta.Image, Metadata: s.Meta.Metadata, Sources: s.Meta.Sources, Packages: s.Meta.Packages, Extras: s.Meta.Extras, Occurrences: make([]byte, len(s.Meta.Occurrences)*20)}
	count := 0
	for _, o := range s.Meta.Occurrences {
		count += len(o.Advisories)
	}
	m.Refs = make([]byte, count*4)
	contexts := map[string]int{}
	pos := 0
	var key bytes.Buffer
	for i, o := range s.Meta.Occurrences {
		ctx := denseContext{o.ImageOrigin, o.DepGroups, o.Groups, o.Licenses, o.Violations}
		key.Reset()
		if err := encoder(&key).Encode(ctx); err != nil {
			panic(err)
		}
		ci, ok := contexts[key.String()]
		if !ok {
			ci = len(m.Contexts)
			contexts[key.String()] = ci
			m.Contexts = append(m.Contexts, ctx)
		}
		row := m.Occurrences[i*20:]
		for j, n := range []int{o.Source, o.Package, ci, pos, len(o.Advisories)} {
			binary.LittleEndian.PutUint32(row[j*4:], uint32(n))
		}
		for _, a := range o.Advisories {
			binary.LittleEndian.PutUint32(m.Refs[pos*4:], uint32(a))
			pos++
		}
	}
	return m
}

// Separate exact-size C buffers permit retaining only the advisory arena.
//
//export store_dense
func store_dense(split C.int, out *unsafe.Pointer, length *C.size_t, advout *unsafe.Pointer, advlength *C.size_t) C.uintptr_t {
	s := normalizeNative()
	meta := denseProjection(s)
	var b bytes.Buffer
	e := encoder(&b)
	if split == 0 {
		e.EncodeMapLen(2)
		e.EncodeString("meta")
	}
	if err := e.Encode(meta); err != nil {
		panic(err)
	}
	var ab bytes.Buffer
	ae := encoder(&ab)
	ae.EncodeArrayLen(len(s.Advisories))
	for _, a := range s.Advisories {
		if err := ae.Encode(packProto{a}); err != nil {
			panic(err)
		}
	}
	if split != 0 {
		*out = C.CBytes(b.Bytes())
		*length = C.size_t(b.Len())
		*advout = C.CBytes(ab.Bytes())
		*advlength = C.size_t(ab.Len())
		return 0
	}
	e.EncodeString("advisories")
	b.Write(ab.Bytes())
	owner := &pinnedResponse{bytes: b.Bytes()}
	owner.pin.Pin(unsafe.SliceData(owner.bytes))
	*out = unsafe.Pointer(unsafe.SliceData(owner.bytes))
	*length = C.size_t(len(owner.bytes))
	return C.uintptr_t(cgo.NewHandle(owner))
}

//export store_records
func store_records(sink C.dense_sink) {
	s := normalizeNative()
	meta := denseProjection(s)
	var b bytes.Buffer
	encoder(&b).Encode(meta)
	C.dense_deliver(sink, unsafe.Pointer(unsafe.SliceData(b.Bytes())), C.size_t(b.Len()), 0)
	for _, a := range s.Advisories {
		b.Reset()
		if err := encoder(&b).Encode(packProto{a}); err != nil {
			panic(err)
		}
		C.dense_deliver(sink, unsafe.Pointer(unsafe.SliceData(b.Bytes())), C.size_t(b.Len()), 1)
	}
}

type directCWriter struct {
	p           unsafe.Pointer
	n, capacity int
}

func (w *directCWriter) Write(b []byte) (int, error) {
	needed := w.n + len(b)
	if needed > w.capacity {
		capacity := w.capacity * 2
		if capacity < needed {
			capacity = needed
		}
		if capacity < 4096 {
			capacity = 4096
		}
		p := C.realloc(w.p, C.size_t(capacity))
		if p == nil {
			return 0, fmt.Errorf("allocation failed")
		}
		w.p = p
		w.capacity = capacity
	}
	copy(unsafe.Slice((*byte)(unsafe.Add(w.p, w.n)), len(b)), b)
	w.n = needed
	return len(b), nil
}
func (w *directCWriter) WriteString(s string) (int, error) {
	return w.Write(unsafe.Slice(unsafe.StringData(s), len(s)))
}
func (w *directCWriter) finish() {
	if w.capacity != w.n {
		p := C.realloc(w.p, C.size_t(w.n))
		if p == nil {
			panic("shrink failed")
		}
		w.p = p
		w.capacity = w.n
	}
}

//export store_dense_direct
func store_dense_direct(out *unsafe.Pointer, length *C.size_t, advout *unsafe.Pointer, advlength *C.size_t) {
	s := normalizeNative()
	meta := denseProjection(s)
	m := &directCWriter{}
	e := msgpack.NewEncoder(m)
	e.SetCustomStructTag("json")
	if err := e.Encode(meta); err != nil {
		panic(err)
	}
	m.finish()
	a := &directCWriter{}
	e = msgpack.NewEncoder(a)
	e.SetCustomStructTag("json")
	e.EncodeArrayLen(len(s.Advisories))
	for _, adv := range s.Advisories {
		if err := e.Encode(packProto{adv}); err != nil {
			panic(err)
		}
	}
	a.finish()
	*out = m.p
	*length = C.size_t(m.n)
	*advout = a.p
	*advlength = C.size_t(a.n)
}

//export store_dense_proto
func store_dense_proto(out *unsafe.Pointer, length *C.size_t, advout *unsafe.Pointer, advlength *C.size_t) {
	s := normalizeNative()
	meta := denseProjection(s)
	m := &directCWriter{}
	e := msgpack.NewEncoder(m)
	e.SetCustomStructTag("json")
	if err := e.Encode(meta); err != nil {
		panic(err)
	}
	m.finish()
	a := &directCWriter{}
	e = msgpack.NewEncoder(a)
	e.SetCustomStructTag("json")
	e.EncodeArrayLen(len(s.Advisories))
	var scratch []byte
	for _, adv := range s.Advisories {
		var err error
		scratch, err = proto.MarshalOptions{}.MarshalAppend(scratch[:0], adv)
		if err != nil {
			panic(err)
		}
		if err = e.EncodeBytes(scratch); err != nil {
			panic(err)
		}
	}
	a.finish()
	*out = m.p
	*length = C.size_t(m.n)
	*advout = a.p
	*advlength = C.size_t(a.n)
}
