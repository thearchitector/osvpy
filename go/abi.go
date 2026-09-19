package main

/*
#include <stdint.h>
#include <stddef.h>
typedef struct {
  uint32_t tag, kind, row, sub;
  double number;
  size_t size;
} osv_value;
*/
import "C"
import (
	"encoding/json"
	"runtime/cgo"
	"sync/atomic"
	"unsafe"
)

const abiVersion = 6

// Count roots held across the Python boundary, not Go heap allocations. This
// makes lifetime checks independent of Go GC and the runtime's heap reuse.
var liveResults atomic.Uint64

//export osv_result_count
func osv_result_count() C.uint64_t { return C.uint64_t(liveResults.Load()) }

func guard(status *C.int) {
	if p := recover(); p != nil {
		*status = C.int(panicStatus(p))
	}
}

//export osv_abi_version
func osv_abi_version() C.int { return abiVersion }

//export osv_batch_create
func osv_batch_create(input *C.char, size C.size_t, out *C.uintptr_t) (status C.int) {
	defer guard(&status)
	*out = 0
	var req request
	if err := json.Unmarshal(unsafe.Slice((*byte)(unsafe.Pointer(input)), int(size)), &req); err != nil {
		panic(err)
	}
	if req.Workers < 1 {
		return 1
	}
	*out = C.uintptr_t(cgo.NewHandle(newOperation(req)))
	return 0
}

//export osv_batch_start
func osv_batch_start(handle C.uintptr_t) (status C.int) {
	defer guard(&status)
	h := cgo.Handle(handle)
	h.Value().(*operation).start()

	return 0
}

//export osv_batch_wait
func osv_batch_wait(handle C.uintptr_t) (status C.int) {
	defer guard(&status)
	h := cgo.Handle(handle)
	return C.int(h.Value().(*operation).wait())
}

//export osv_batch_cancel
func osv_batch_cancel(handle C.uintptr_t) (status C.int) {
	defer guard(&status)
	h := cgo.Handle(handle)
	h.Value().(*operation).cancel()

	return 0
}

//export osv_batch_release
func osv_batch_release(handle C.uintptr_t) (status C.int) {
	defer guard(&status)
	h := cgo.Handle(handle)
	h.Value().(*operation).release()
	h.Delete()
	return 0
}

//export osv_batch_finish
func osv_batch_finish(handle C.uintptr_t, out *C.uintptr_t) (status C.int) {
	defer guard(&status)
	*out = 0
	r, s := cgo.Handle(handle).Value().(*operation).finish()
	if s != 0 {
		return C.int(s)
	}
	*out = C.uintptr_t(cgo.NewHandle(r))
	liveResults.Add(1)
	return 0
}

//export osv_result_release
func osv_result_release(handle C.uintptr_t) (status C.int) {
	defer guard(&status)
	cgo.Handle(handle).Delete()
	liveResults.Add(^uint64(0))
	return 0
}

type nativeValue struct {
	tag, kind, row, sub uint32
	number              float64
	text                string
}

func textValue(s string) nativeValue { return nativeValue{tag: 1, text: s} }
func boolValue(b bool) nativeValue {
	if b {
		return nativeValue{tag: 2, number: 1}
	}
	return nativeValue{tag: 2}
}
func refValue(kind, row, sub uint32) nativeValue {
	return nativeValue{tag: 4, kind: kind, row: row, sub: sub}
}
func seqValue(n int) nativeValue { return nativeValue{tag: 5, number: float64(checked(n))} }

func (r *reportStore) optionalStringValue(id uint32) nativeValue {
	if id == 0 {
		return nativeValue{}
	}
	return textValue(r.stringAt(id))
}
func optionalBoolValue(tag uint8) nativeValue {
	if tag == 0 {
		return nativeValue{}
	}
	return boolValue(tag == 2)
}
func (r *reportStore) stringListValue(s span, index int64) nativeValue {
	if index < 0 {
		return seqValue(int(s.Count))
	}
	if uint64(index) >= uint64(s.Count) {
		panic("invalid index")
	}
	return textValue(r.stringAt(*r.Words.At(int(s.Start) + int(index))))
}
func recordListValue(s span, width, kind, row uint32, index int64) nativeValue {
	n := s.Count / width
	if index < 0 {
		return seqValue(int(n))
	}
	if uint64(index) >= uint64(n) {
		panic("invalid index")
	}
	return refValue(kind, row, uint32(index))
}

func (r *reportStore) indexValue(id int, row, kind uint32, index int64) nativeValue {
	idx := &r.Indexes[id]
	start, stop := *idx.Offsets.At(int(row)), *idx.Offsets.At(int(row) + 1)
	if index < 0 {
		return seqValue(int(stop - start))
	}
	if uint64(index) >= uint64(stop-start) {
		panic("invalid index")
	}
	member := start + uint32(index)
	if !idx.Range {
		member = *idx.Members.At(int(member))
	}
	return refValue(kind, member, 0)
}

func (r *reportStore) value(kind, row, sub, field uint32, index int64) nativeValue {
	switch kind {
	case 1:
		switch field {
		case 1:
			if index < 0 {
				return seqValue(r.Images.Len())
			}
			if uint64(index) >= uint64(r.Images.Len()) {
				panic("invalid index")
			}
			return refValue(2, uint32(index), 0)
		case 2:
			if index < 0 {
				return seqValue(r.Packages.Len())
			}
			if uint64(index) >= uint64(r.Packages.Len()) {
				panic("invalid index")
			}
			return refValue(3, uint32(index), 0)
		case 3:
			if index < 0 {
				return seqValue(r.Vulnerabilities.Len())
			}
			if uint64(index) >= uint64(r.Vulnerabilities.Len()) {
				panic("invalid index")
			}
			return refValue(4, uint32(index), 0)
		case 4:
			if index < 0 {
				return seqValue(r.AdvisorySources.Len())
			}
			if uint64(index) >= uint64(r.AdvisorySources.Len()) {
				panic("invalid index")
			}
			return refValue(5, uint32(index), 0)
		case 5:
			if index < 0 {
				return seqValue(r.Findings.Len())
			}
			if uint64(index) >= uint64(r.Findings.Len()) {
				panic("invalid index")
			}
			return refValue(7, uint32(index), 0)
		}
	case 2:
		v := r.Images.At(int(row))
		switch field {
		case 1:
			return textValue(v.Requested)
		case 2:
			if v.OS == nil {
				return nativeValue{}
			}
			return textValue(*v.OS)
		case 3:
			return textValue(v.Status)
		case 4:
			return refValue(12, row, 0)
		case 5:
			if index < 0 {
				return seqValue(len(v.Diagnostics))
			}
			if uint64(index) >= uint64(len(v.Diagnostics)) {
				panic("invalid index")
			}
			return refValue(13, row, uint32(index))
		case 6:
			return r.indexValue(0, row, 6, index)
		case 7:
			return r.indexValue(1, row, 7, index)
		case 8:
			return r.indexValue(3, row, 3, index)
		case 9:
			return r.indexValue(4, row, 3, index)
		case 10:
			return r.indexValue(5, row, 3, index)
		case 11:
			return r.indexValue(6, row, 4, index)
		}
	case 3:
		v := r.Packages.At(int(row))
		switch field {
		case 1:
			return textValue(r.stringAt(v.Name))
		case 2:
			return textValue(r.stringAt(v.Version))
		case 3:
			return textValue(r.stringAt(v.Ecosystem))
		case 4:
			return textValue(r.stringAt(v.Commit))
		case 5:
			return textValue(r.stringAt(v.OSPackageName))
		case 6:
			return textValue(r.stringAt(v.PURL))
		case 7:
			return r.indexValue(7, row, 2, index)
		case 8:
			return r.indexValue(8, row, 2, index)
		case 9:
			return r.indexValue(9, row, 2, index)
		case 10:
			return r.indexValue(10, row, 2, index)
		case 11:
			return r.indexValue(15, row, 7, index)
		}
	case 4:
		v := r.Vulnerabilities.At(int(row))
		switch field {
		case 1:
			return textValue(r.stringAt(v.ID))
		case 2:
			return r.stringListValue(v.Aliases, index)
		case 3:
			return r.indexValue(11, row, 2, index)
		case 4:
			return r.indexValue(13, row, 7, index)
		}
	case 5:
		v := r.AdvisorySources.At(int(row))
		switch field {
		case 1:
			return textValue(r.stringAt(v.ID))
		case 2:
			return r.stringListValue(v.Aliases, index)
		case 3:
			return textValue(r.stringAt(v.Summary))
		case 4:
			return r.optionalStringValue(v.Modified)
		case 5:
			return r.optionalStringValue(v.Published)
		case 6:
			return r.optionalStringValue(v.Withdrawn)
		case 7:
			return r.optionalStringValue(v.DatabaseSeverity)
		case 8:
			return recordListValue(v.Severities, 3, 14, row, index)
		case 9:
			return recordListValue(v.References, 2, 15, row, index)
		case 10:
			return r.indexValue(12, row, 2, index)
		case 11:
			return r.indexValue(14, row, 7, index)
		}
	case 6:
		v := r.Occurrences.At(int(row))
		switch field {
		case 1:
			return refValue(2, v.Image, 0)
		case 2:
			return refValue(3, v.Package, 0)
		case 3:
			return refValue(8, v.Context, 0)
		case 4:
			return refValue(10, v.License, 0)
		case 5:
			return r.indexValue(2, row, 7, index)
		}
	case 7:
		v := r.Findings.At(int(row))
		switch field {
		case 1:
			return refValue(6, v.Occurrence, 0)
		case 2:
			return refValue(5, v.Advisory, 0)
		case 3:
			return refValue(11, v.Fix, 0)
		case 4:
			return refValue(9, v.Assessment, 0)
		case 5:
			return refValue(4, *r.AdvisoryVulnerabilities.At(int(v.Advisory)), 0)
		}
	case 8:
		v := r.Contexts.At(int(row))
		switch field {
		case 1:
			return textValue(r.stringAt(v.Path))
		case 2:
			return textValue(r.stringAt(v.SourceType))
		case 3:
			return r.optionalStringValue(v.Layer)
		case 4:
			return r.stringListValue(v.DependencyGroups, index)

		}
	case 9:
		v := r.Assessments.At(int(row))
		switch field {
		case 1:
			return optionalBoolValue(v.Called)
		case 2:
			return optionalBoolValue(v.Unimportant)
		case 3:
			return textValue(r.stringAt(v.MaxSeverity))

		}
	case 10:
		v := r.Licenses.At(int(row))
		switch field {
		case 1:
			return r.stringListValue(v.Licenses, index)
		case 2:
			if v.Policy.Start == nilSpanStart {
				return nativeValue{}
			}
			return r.stringListValue(v.Policy, index)
		case 3:
			return r.stringListValue(v.Violations, index)
		case 4:
			return textValue(statusNames[v.Status])

		}
	case 11:
		v := r.Fixes.At(int(row))
		switch field {
		case 1:
			return r.stringListValue(v.Versions, index)
		case 2:
			return textValue(statusNames[v.Status])
		case 3:
			return recordListValue(v.Severities, 3, 16, row, index)
		case 4:
			return r.stringListValue(v.Urgencies, index)

		}
	case 12:
		v := r.Images.At(int(row)).Metadata
		switch field {
		case 1:
			if index < 0 {
				return seqValue(len(v.Languages))
			}
			if uint64(index) >= uint64(len(v.Languages)) {
				panic("invalid index")
			}
			return textValue(v.Languages[index])
		case 2:
			return textValue(v.ScannerVersion)
		case 3:
			return boolValue(v.AllPackages)
		case 4:
			return textValue(v.ImageDigest)
		case 5:
			return textValue(v.ImagePlatform)
		case 6:
			return nativeValue{tag: 3, number: v.DurationSeconds}
		case 7:
			return boolValue(v.NoPackages)
		}
	case 13:
		v := r.Images.At(int(row)).Diagnostics[sub]
		switch field {
		case 1:
			return textValue(v.Code)
		case 2:
			return textValue(v.Message)
		}
	case 14:
		s := r.AdvisorySources.At(int(row)).Severities
		if sub >= s.Count/3 || field < 1 || field > 3 {
			panic("invalid property")
		}
		return textValue(r.stringAt(*r.Words.At(int(s.Start) + int(sub)*3 + int(field) - 1)))
	case 15:
		s := r.AdvisorySources.At(int(row)).References
		if sub >= s.Count/2 || field < 1 || field > 2 {
			panic("invalid property")
		}
		return textValue(r.stringAt(*r.Words.At(int(s.Start) + int(sub)*2 + int(field) - 1)))
	case 16:
		s := r.Fixes.At(int(row)).Severities
		if sub >= s.Count/3 || field < 1 || field > 3 {
			panic("invalid property")
		}
		return textValue(r.stringAt(*r.Words.At(int(s.Start) + int(sub)*3 + int(field) - 1)))
	}
	panic("invalid property")
}

// osv_result_get copies strings into the caller's buffer. size reports the
// required byte count; an undersized buffer is untouched and can be retried.
// No pointer into the Go heap survives this call.
//
//export osv_result_get
func osv_result_get(handle C.uintptr_t, kind, row, sub, field C.uint32_t, index C.int64_t, buffer *C.char, capacity C.size_t, out *C.osv_value) (status C.int) {
	defer guard(&status)
	*out = C.osv_value{}
	v := cgo.Handle(handle).Value().(*reportStore).value(uint32(kind), uint32(row), uint32(sub), uint32(field), int64(index))
	out.tag, out.kind, out.row, out.sub = C.uint32_t(v.tag), C.uint32_t(v.kind), C.uint32_t(v.row), C.uint32_t(v.sub)
	out.number, out.size = C.double(v.number), C.size_t(len(v.text))
	if len(v.text) > 0 && uint64(capacity) >= uint64(len(v.text)) {
		copy(unsafe.Slice((*byte)(unsafe.Pointer(buffer)), len(v.text)), v.text)
	}
	return 0
}
