package main

/*
#include <stdlib.h>
#include <stdint.h>
typedef void (*store_sink)(const void*, size_t);
static void store_deliver(store_sink sink, const void *p, size_t n) { sink(p, n); }
*/
import "C"

import (
	"bytes"
	"encoding/json"
	"runtime"
	"runtime/cgo"
	"sort"
	"time"
	"unsafe"

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/vmihailenco/msgpack/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type occurrence struct {
	Source      int                        `json:"source"`
	Package     int                        `json:"package"`
	ImageOrigin *models.ImageOriginDetails `json:"image_origin_details,omitempty"`
	DepGroups   []string                   `json:"dependency_groups,omitempty"`
	Groups      []models.GroupInfo         `json:"groups,omitempty"`
	Licenses    []models.License           `json:"licenses,omitempty"`
	Violations  []models.License           `json:"license_violations,omitempty"`
	Advisories  []int                      `json:"advisories"`
}
type sourceRecord struct {
	Source models.SourceInfo `json:"source"`
	// Keep source annotations without projecting through JSON.
	Signals any `json:"experimental_pes,omitempty"`
}
type storeMeta struct {
	Image       string               `json:"image"`
	Metadata    json.RawMessage      `json:"metadata"`
	Sources     []sourceRecord       `json:"sources"`
	Packages    []models.PackageInfo `json:"packages"`
	Occurrences []occurrence         `json:"occurrences"`
	// Preserve remaining full-result fields through a JSON projection for this
	// controlled experiment. Identical overhead for every measured transport.
	Extras json.RawMessage `json:"extras"`
}
type normalizedStore struct {
	Meta       storeMeta
	Advisories []*osvschema.Vulnerability
}

var currentStore *normalizedStore
var fastEquality bool
var canonicalBodies bool

//export store_fast_equality
func store_fast_equality(enabled C.int) { fastEquality = enabled != 0 }

func normalizeNative() *normalizedStore {
	s := &normalizedStore{}
	r := value.Result
	s.Meta.Image = r.Image
	s.Meta.Metadata = r.Metadata
	extra := *r
	extra.Results = nil
	var err error
	s.Meta.Extras, err = json.Marshal(extra)
	if err != nil {
		panic(err)
	}
	packageIndex := map[models.PackageInfo]int{}
	advisoryIndex := map[string][]int{}
	pointers := map[*osvschema.Vulnerability]int{}
	canonical := map[int][]byte{}
	var scratch []byte
	deterministic := proto.MarshalOptions{Deterministic: true}
	for si, source := range r.Results {
		s.Meta.Sources = append(s.Meta.Sources, sourceRecord{source.Source, source.ExperimentalPES})
		for _, p := range source.Packages {
			info := p.Package
			info.ImageOrigin = nil
			info.Inventory = nil
			pi, ok := packageIndex[info]
			if !ok {
				pi = len(s.Meta.Packages)
				packageIndex[info] = pi
				s.Meta.Packages = append(s.Meta.Packages, info)
			}
			o := occurrence{Source: si, Package: pi, ImageOrigin: p.Package.ImageOrigin, DepGroups: p.DepGroups, Groups: p.Groups, Licenses: p.Licenses, Violations: p.LicenseViolations, Advisories: make([]int, 0, len(p.Vulnerabilities))}
			for _, a := range p.Vulnerabilities {
				ai, ok := pointers[a]
				if !ok {
					ai = -1
					candidates := advisoryIndex[a.GetId()]
					if fastEquality && len(candidates) > 0 {
						var err error
						scratch, err = deterministic.MarshalAppend(scratch[:0], a)
						if err != nil {
							panic(err)
						}
						for _, candidate := range candidates {
							encoded, ok := canonical[candidate]
							if !ok {
								encoded, err = deterministic.Marshal(s.Advisories[candidate])
								if err != nil {
									panic(err)
								}
								canonical[candidate] = encoded
							}
							if bytes.Equal(scratch, encoded) {
								ai = candidate
								break
							}
						}
					} else {
						for _, candidate := range candidates {
							if proto.Equal(a, s.Advisories[candidate]) {
								ai = candidate
								break
							}
						}
					}
					if ai < 0 {
						ai = len(s.Advisories)
						s.Advisories = append(s.Advisories, a)
						advisoryIndex[a.GetId()] = append(advisoryIndex[a.GetId()], ai)
					}
					pointers[a] = ai
				}
				o.Advisories = append(o.Advisories, ai)
			}
			s.Meta.Occurrences = append(s.Meta.Occurrences, o)
		}
	}
	return s
}

// Encode protobuf values directly, without ProtoJSON or a map intermediary.
type packProto struct{ message proto.Message }

func (p packProto) EncodeMsgpack(e *msgpack.Encoder) error {
	return encodeProto(e, p.message.ProtoReflect())
}
func encodeProto(e *msgpack.Encoder, m protoreflect.Message) error {
	switch v := m.Interface().(type) {
	case *timestamppb.Timestamp:
		return e.EncodeString(v.AsTime().UTC().Format(time.RFC3339Nano))
	case *structpb.Struct:
		if err := e.EncodeMapLen(len(v.Fields)); err != nil {
			return err
		}
		keys := make([]string, 0, len(v.Fields))
		for k := range v.Fields {
			keys = append(keys, k)
		}
		if canonicalBodies {
			sort.Strings(keys)
		}
		for _, k := range keys {
			field := v.Fields[k]
			if err := e.EncodeString(k); err != nil {
				return err
			}
			if err := encodeProto(e, field.ProtoReflect()); err != nil {
				return err
			}
		}
		return nil
	case *structpb.ListValue:
		if err := e.EncodeArrayLen(len(v.Values)); err != nil {
			return err
		}
		for _, v := range v.Values {
			if err := encodeProto(e, v.ProtoReflect()); err != nil {
				return err
			}
		}
		return nil
	case *structpb.Value:
		switch x := v.Kind.(type) {
		case *structpb.Value_NullValue:
			return e.EncodeNil()
		case *structpb.Value_BoolValue:
			return e.EncodeBool(x.BoolValue)
		case *structpb.Value_NumberValue:
			return e.EncodeFloat64(x.NumberValue)
		case *structpb.Value_StringValue:
			return e.EncodeString(x.StringValue)
		case *structpb.Value_StructValue:
			return encodeProto(e, x.StructValue.ProtoReflect())
		case *structpb.Value_ListValue:
			return encodeProto(e, x.ListValue.ProtoReflect())
		}
	}
	count := 0
	m.Range(func(protoreflect.FieldDescriptor, protoreflect.Value) bool { count++; return true })
	if err := e.EncodeMapLen(count); err != nil {
		return err
	}
	var failure error
	visit := func(f protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if failure = e.EncodeString(f.JSONName()); failure != nil {
			return false
		}
		if f.IsList() {
			l := v.List()
			failure = e.EncodeArrayLen(l.Len())
			for i := 0; i < l.Len() && failure == nil; i++ {
				failure = encodeProtoScalar(e, f, l.Get(i))
			}
		} else {
			failure = encodeProtoScalar(e, f, v)
		}
		return failure == nil
	}
	if canonicalBodies {
		fields := m.Descriptor().Fields()
		for i := 0; i < fields.Len(); i++ {
			f := fields.Get(i)
			if m.Has(f) && !visit(f, m.Get(f)) {
				break
			}
		}
	} else {
		m.Range(visit)
	}
	return failure
}
func encodeProtoScalar(e *msgpack.Encoder, f protoreflect.FieldDescriptor, v protoreflect.Value) error {
	switch f.Kind() {
	case protoreflect.MessageKind:
		return encodeProto(e, v.Message())
	case protoreflect.EnumKind:
		n := f.Enum().Values().ByNumber(v.Enum())
		if n == nil {
			return e.EncodeInt(int64(v.Enum()))
		}
		return e.EncodeString(string(n.Name()))
	default:
		return e.Encode(v.Interface())
	}
}
func encoder(b *bytes.Buffer) *msgpack.Encoder {
	e := msgpack.NewEncoder(b)
	e.SetCustomStructTag("json")
	return e
}

func encodeStore(s *normalizedStore, mode int) []byte {
	if mode == 0 {
		adv := make([]advisoryView, len(s.Advisories))
		for i, a := range s.Advisories {
			adv[i] = advisoryView{a}
		}
		b, err := json.Marshal(struct {
			Meta       storeMeta      `json:"meta"`
			Advisories []advisoryView `json:"advisories"`
		}{s.Meta, adv})
		if err != nil {
			panic(err)
		}
		return b
	}
	var b bytes.Buffer
	e := encoder(&b)
	// Metadata JSON RawMessage fields are bytes on MessagePack. Decoded separately.
	if err := e.EncodeMapLen(2); err != nil {
		panic(err)
	}
	e.EncodeString("meta")
	if err := e.Encode(s.Meta); err != nil {
		panic(err)
	}
	e.EncodeString("advisories")
	e.EncodeArrayLen(len(s.Advisories))
	for _, a := range s.Advisories {
		var err error
		if mode == 1 {
			err = e.Encode(packProto{a})
		} else {
			var raw []byte
			if mode == 3 {
				raw, err = proto.Marshal(a)
			} else {
				var body bytes.Buffer
				err = encoder(&body).Encode(packProto{a})
				raw = body.Bytes()
			}
			if err == nil {
				err = e.EncodeBytes(raw)
			}
		}
		if err != nil {
			panic(err)
		}
	}
	return b.Bytes()
}

//export store_prepare
func store_prepare() { currentStore = normalizeNative() }

//export store_build
func store_build(mode C.int, handoff C.int, out *unsafe.Pointer, length *C.size_t, sink C.store_sink) C.uintptr_t {
	s := normalizeNative()
	if mode == 4 {
		return C.uintptr_t(cgo.NewHandle(s))
	}
	var b []byte
	if mode == 5 {
		b = flatStore(s)
	} else {
		b = encodeStore(s, int(mode))
	}
	*length = C.size_t(len(b))
	if handoff == 0 {
		C.store_deliver(sink, unsafe.Pointer(unsafe.SliceData(b)), C.size_t(len(b)))
		runtime.KeepAlive(b)
		return 0
	}
	if handoff == 2 {
		*out = C.CBytes(b)
		return 0
	}
	owner := &pinnedResponse{bytes: b}
	owner.pin.Pin(unsafe.SliceData(b))
	*out = unsafe.Pointer(unsafe.SliceData(b))
	return C.uintptr_t(cgo.NewHandle(owner))
}

//export store_drop_input
func store_drop_input() { value = envelope{}; currentStore = nil; runtime.GC() }

//export store_native_meta
func store_native_meta(id C.uintptr_t, sink C.store_sink) {
	s := cgo.Handle(id).Value().(*normalizedStore)
	var b bytes.Buffer
	encoder(&b).Encode(s.Meta)
	C.store_deliver(sink, unsafe.Pointer(unsafe.SliceData(b.Bytes())), C.size_t(b.Len()))
}

//export store_native_count
func store_native_count(id C.uintptr_t) C.size_t {
	return C.size_t(len(cgo.Handle(id).Value().(*normalizedStore).Meta.Occurrences))
}

//export store_native_ref
func store_native_ref(id C.uintptr_t, occ C.int, adv C.int) C.int {
	refs := cgo.Handle(id).Value().(*normalizedStore).Meta.Occurrences[int(occ)].Advisories
	if adv < 0 {
		return C.int(len(refs))
	}
	return C.int(refs[int(adv)])
}

//export store_native_advisory
func store_native_advisory(id C.uintptr_t, index C.int, field C.int, sink C.store_sink) {
	a := cgo.Handle(id).Value().(*normalizedStore).Advisories[int(index)]
	if field < 2 {
		v := a.GetId()
		if field == 1 {
			v = a.GetDetails()
		}
		C.store_deliver(sink, unsafe.Pointer(unsafe.StringData(v)), C.size_t(len(v)))
		return
	}
	var b bytes.Buffer
	encoder(&b).Encode(packProto{a})
	C.store_deliver(sink, unsafe.Pointer(unsafe.SliceData(b.Bytes())), C.size_t(b.Len()))
}

//export store_descriptors
func store_descriptors(sink C.store_sink) {
	seen := map[string]bool{}
	set := &descriptorpb.FileDescriptorSet{}
	var add func(protoreflect.FileDescriptor)
	add = func(f protoreflect.FileDescriptor) {
		if seen[f.Path()] {
			return
		}
		seen[f.Path()] = true
		for i := 0; i < f.Imports().Len(); i++ {
			add(f.Imports().Get(i).FileDescriptor)
		}
		set.File = append(set.File, protodesc.ToFileDescriptorProto(f))
	}
	add((&osvschema.Vulnerability{}).ProtoReflect().Descriptor().ParentFile())
	b, _ := proto.Marshal(set)
	C.store_deliver(sink, unsafe.Pointer(unsafe.SliceData(b)), C.size_t(len(b)))
}

// FlatBuffers envelope: metadata blob plus table vector. ID/details are direct
// fields; remaining advisory fields use MessagePack so strings are not duplicated.
func flatStore(s *normalizedStore) []byte {
	b := flatbuffers.NewBuilder(1024)
	var meta bytes.Buffer
	encoder(&meta).Encode(s.Meta)
	mo := b.CreateByteVector(meta.Bytes())
	offsets := make([]flatbuffers.UOffsetT, len(s.Advisories))
	for i, a := range s.Advisories {
		clone := *a
		clone.Id = ""
		clone.Details = ""
		var body bytes.Buffer
		encoder(&body).Encode(packProto{&clone})
		po := b.CreateByteVector(body.Bytes())
		id := b.CreateString(a.GetId())
		details := b.CreateString(a.GetDetails())
		b.StartObject(3)
		b.PrependUOffsetTSlot(0, id, 0)
		b.PrependUOffsetTSlot(1, details, 0)
		b.PrependUOffsetTSlot(2, po, 0)
		offsets[i] = b.EndObject()
	}
	b.StartVector(4, len(offsets), 4)
	for i := len(offsets) - 1; i >= 0; i-- {
		b.PrependUOffsetT(offsets[i])
	}
	ao := b.EndVector(len(offsets))
	b.StartObject(2)
	b.PrependUOffsetTSlot(0, mo, 0)
	b.PrependUOffsetTSlot(1, ao, 0)
	root := b.EndObject()
	b.Finish(root)
	return b.FinishedBytes()
}
