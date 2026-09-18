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
	"unsafe"
)

const abiVersion = 6

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
	return 0
}

//export osv_result_release
func osv_result_release(handle C.uintptr_t) (status C.int) {
	defer guard(&status)
	cgo.Handle(handle).Delete()
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
func (r *reportStore) value(kind, row, sub, field uint32, index int64) nativeValue {
	switch kind {
	case 1:
		switch field {
		case 1:
			if index < 0 {
				return seqValue(len(r.Images))
			}
			if uint64(index) >= uint64(len(r.Images)) {
				panic("invalid index")
			}
			return refValue(2, uint32(index), 0)
		case 2:
			if index < 0 {
				return seqValue(len(r.Packages))
			}
			if uint64(index) >= uint64(len(r.Packages)) {
				panic("invalid index")
			}
			return refValue(3, uint32(index), 0)
		case 3:
			if index < 0 {
				return seqValue(len(r.Vulnerabilities))
			}
			if uint64(index) >= uint64(len(r.Vulnerabilities)) {
				panic("invalid index")
			}
			return refValue(4, uint32(index), 0)
		case 4:
			if index < 0 {
				return seqValue(len(r.AdvisorySources))
			}
			if uint64(index) >= uint64(len(r.AdvisorySources)) {
				panic("invalid index")
			}
			return refValue(5, uint32(index), 0)
		case 5:
			if index < 0 {
				return seqValue(len(r.Findings))
			}
			if uint64(index) >= uint64(len(r.Findings)) {
				panic("invalid index")
			}
			return refValue(7, uint32(index), 0)
		}
	case 2:
		v := &r.Images[row]
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
			idx := &r.Indexes[0]
			start, stop := idx.Offsets[row], idx.Offsets[row+1]
			if index < 0 {
				return seqValue(int(stop - start))
			}
			if uint64(index) >= uint64(stop-start) {
				panic("invalid index")
			}
			member := start + uint32(index)
			if !idx.Range {
				member = idx.Members[member]
			}
			return refValue(6, member, 0)
		case 7:
			idx := &r.Indexes[1]
			start, stop := idx.Offsets[row], idx.Offsets[row+1]
			if index < 0 {
				return seqValue(int(stop - start))
			}
			if uint64(index) >= uint64(stop-start) {
				panic("invalid index")
			}
			member := start + uint32(index)
			if !idx.Range {
				member = idx.Members[member]
			}
			return refValue(7, member, 0)
		case 8:
			idx := &r.Indexes[3]
			start, stop := idx.Offsets[row], idx.Offsets[row+1]
			if index < 0 {
				return seqValue(int(stop - start))
			}
			if uint64(index) >= uint64(stop-start) {
				panic("invalid index")
			}
			member := start + uint32(index)
			if !idx.Range {
				member = idx.Members[member]
			}
			return refValue(3, member, 0)
		case 9:
			idx := &r.Indexes[4]
			start, stop := idx.Offsets[row], idx.Offsets[row+1]
			if index < 0 {
				return seqValue(int(stop - start))
			}
			if uint64(index) >= uint64(stop-start) {
				panic("invalid index")
			}
			member := start + uint32(index)
			if !idx.Range {
				member = idx.Members[member]
			}
			return refValue(3, member, 0)
		case 10:
			idx := &r.Indexes[5]
			start, stop := idx.Offsets[row], idx.Offsets[row+1]
			if index < 0 {
				return seqValue(int(stop - start))
			}
			if uint64(index) >= uint64(stop-start) {
				panic("invalid index")
			}
			member := start + uint32(index)
			if !idx.Range {
				member = idx.Members[member]
			}
			return refValue(3, member, 0)
		case 11:
			idx := &r.Indexes[6]
			start, stop := idx.Offsets[row], idx.Offsets[row+1]
			if index < 0 {
				return seqValue(int(stop - start))
			}
			if uint64(index) >= uint64(stop-start) {
				panic("invalid index")
			}
			member := start + uint32(index)
			if !idx.Range {
				member = idx.Members[member]
			}
			return refValue(4, member, 0)
		}
	case 3:
		v := &r.Packages[row]
		switch field {
		case 1:
			return textValue(v.Name)
		case 2:
			return textValue(v.Version)
		case 3:
			return textValue(v.Ecosystem)
		case 4:
			return textValue(v.Commit)
		case 5:
			return textValue(v.OSPackageName)
		case 6:
			return textValue(v.PURL)
		case 7:
			idx := &r.Indexes[7]
			start, stop := idx.Offsets[row], idx.Offsets[row+1]
			if index < 0 {
				return seqValue(int(stop - start))
			}
			if uint64(index) >= uint64(stop-start) {
				panic("invalid index")
			}
			member := start + uint32(index)
			if !idx.Range {
				member = idx.Members[member]
			}
			return refValue(2, member, 0)
		case 8:
			idx := &r.Indexes[8]
			start, stop := idx.Offsets[row], idx.Offsets[row+1]
			if index < 0 {
				return seqValue(int(stop - start))
			}
			if uint64(index) >= uint64(stop-start) {
				panic("invalid index")
			}
			member := start + uint32(index)
			if !idx.Range {
				member = idx.Members[member]
			}
			return refValue(2, member, 0)
		case 9:
			idx := &r.Indexes[9]
			start, stop := idx.Offsets[row], idx.Offsets[row+1]
			if index < 0 {
				return seqValue(int(stop - start))
			}
			if uint64(index) >= uint64(stop-start) {
				panic("invalid index")
			}
			member := start + uint32(index)
			if !idx.Range {
				member = idx.Members[member]
			}
			return refValue(2, member, 0)
		case 10:
			idx := &r.Indexes[10]
			start, stop := idx.Offsets[row], idx.Offsets[row+1]
			if index < 0 {
				return seqValue(int(stop - start))
			}
			if uint64(index) >= uint64(stop-start) {
				panic("invalid index")
			}
			member := start + uint32(index)
			if !idx.Range {
				member = idx.Members[member]
			}
			return refValue(2, member, 0)
		case 11:
			idx := &r.Indexes[15]
			start, stop := idx.Offsets[row], idx.Offsets[row+1]
			if index < 0 {
				return seqValue(int(stop - start))
			}
			if uint64(index) >= uint64(stop-start) {
				panic("invalid index")
			}
			member := start + uint32(index)
			if !idx.Range {
				member = idx.Members[member]
			}
			return refValue(7, member, 0)
		}
	case 4:
		v := &r.Vulnerabilities[row]
		switch field {
		case 1:
			return textValue(v.ID)
		case 2:
			if index < 0 {
				return seqValue(len(v.Aliases))
			}
			if uint64(index) >= uint64(len(v.Aliases)) {
				panic("invalid index")
			}
			return textValue(v.Aliases[index])
		case 3:
			idx := &r.Indexes[11]
			start, stop := idx.Offsets[row], idx.Offsets[row+1]
			if index < 0 {
				return seqValue(int(stop - start))
			}
			if uint64(index) >= uint64(stop-start) {
				panic("invalid index")
			}
			member := start + uint32(index)
			if !idx.Range {
				member = idx.Members[member]
			}
			return refValue(2, member, 0)
		case 4:
			idx := &r.Indexes[13]
			start, stop := idx.Offsets[row], idx.Offsets[row+1]
			if index < 0 {
				return seqValue(int(stop - start))
			}
			if uint64(index) >= uint64(stop-start) {
				panic("invalid index")
			}
			member := start + uint32(index)
			if !idx.Range {
				member = idx.Members[member]
			}
			return refValue(7, member, 0)
		}
	case 5:
		v := &r.AdvisorySources[row]
		switch field {
		case 1:
			return textValue(v.ID)
		case 2:
			if index < 0 {
				return seqValue(len(v.Aliases))
			}
			if uint64(index) >= uint64(len(v.Aliases)) {
				panic("invalid index")
			}
			return textValue(v.Aliases[index])
		case 3:
			return textValue(v.Summary)
		case 4:
			if v.Modified == nil {
				return nativeValue{}
			}
			return textValue(*v.Modified)
		case 5:
			if v.Published == nil {
				return nativeValue{}
			}
			return textValue(*v.Published)
		case 6:
			if v.Withdrawn == nil {
				return nativeValue{}
			}
			return textValue(*v.Withdrawn)
		case 7:
			if v.DatabaseSeverity == nil {
				return nativeValue{}
			}
			return textValue(*v.DatabaseSeverity)
		case 8:
			if index < 0 {
				return seqValue(len(v.Severities))
			}
			if uint64(index) >= uint64(len(v.Severities)) {
				panic("invalid index")
			}
			return refValue(14, row, uint32(index))
		case 9:
			if index < 0 {
				return seqValue(len(v.References))
			}
			if uint64(index) >= uint64(len(v.References)) {
				panic("invalid index")
			}
			return refValue(15, row, uint32(index))
		case 10:
			idx := &r.Indexes[12]
			start, stop := idx.Offsets[row], idx.Offsets[row+1]
			if index < 0 {
				return seqValue(int(stop - start))
			}
			if uint64(index) >= uint64(stop-start) {
				panic("invalid index")
			}
			member := start + uint32(index)
			if !idx.Range {
				member = idx.Members[member]
			}
			return refValue(2, member, 0)
		case 11:
			idx := &r.Indexes[14]
			start, stop := idx.Offsets[row], idx.Offsets[row+1]
			if index < 0 {
				return seqValue(int(stop - start))
			}
			if uint64(index) >= uint64(stop-start) {
				panic("invalid index")
			}
			member := start + uint32(index)
			if !idx.Range {
				member = idx.Members[member]
			}
			return refValue(7, member, 0)
		}
	case 6:
		v := &r.Occurrences[row]
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
			idx := &r.Indexes[2]
			start, stop := idx.Offsets[row], idx.Offsets[row+1]
			if index < 0 {
				return seqValue(int(stop - start))
			}
			if uint64(index) >= uint64(stop-start) {
				panic("invalid index")
			}
			member := start + uint32(index)
			if !idx.Range {
				member = idx.Members[member]
			}
			return refValue(7, member, 0)
		}
	case 7:
		v := &r.Findings[row]
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
			return refValue(4, v.Vulnerability, 0)
		}
	case 8:
		v := &r.Contexts[row]
		switch field {
		case 1:
			return textValue(v.Path)
		case 2:
			return textValue(v.SourceType)
		case 3:
			if v.Layer == nil {
				return nativeValue{}
			}
			return textValue(*v.Layer)
		case 4:
			if index < 0 {
				return seqValue(len(v.DependencyGroups))
			}
			if uint64(index) >= uint64(len(v.DependencyGroups)) {
				panic("invalid index")
			}
			return textValue(v.DependencyGroups[index])
		}
	case 9:
		v := &r.Assessments[row]
		switch field {
		case 1:
			if v.Called == nil {
				return nativeValue{}
			}
			return boolValue(*v.Called)
		case 2:
			if v.Unimportant == nil {
				return nativeValue{}
			}
			return boolValue(*v.Unimportant)
		case 3:
			return textValue(v.MaxSeverity)
		}
	case 10:
		v := &r.Licenses[row]
		switch field {
		case 1:
			if index < 0 {
				return seqValue(len(v.Licenses))
			}
			if uint64(index) >= uint64(len(v.Licenses)) {
				panic("invalid index")
			}
			return textValue(v.Licenses[index])
		case 2:
			if v.Policy == nil {
				return nativeValue{}
			}
			if index < 0 {
				return seqValue(len(v.Policy))
			}
			if uint64(index) >= uint64(len(v.Policy)) {
				panic("invalid index")
			}
			return textValue(v.Policy[index])
		case 3:
			if index < 0 {
				return seqValue(len(v.Violations))
			}
			if uint64(index) >= uint64(len(v.Violations)) {
				panic("invalid index")
			}
			return textValue(v.Violations[index])
		case 4:
			return textValue(v.Status)
		}
	case 11:
		v := &r.Fixes[row]
		switch field {
		case 1:
			if index < 0 {
				return seqValue(len(v.Versions))
			}
			if uint64(index) >= uint64(len(v.Versions)) {
				panic("invalid index")
			}
			return textValue(v.Versions[index])
		case 2:
			return textValue(v.Status)
		case 3:
			if index < 0 {
				return seqValue(len(v.Severities))
			}
			if uint64(index) >= uint64(len(v.Severities)) {
				panic("invalid index")
			}
			return refValue(16, row, uint32(index))
		case 4:
			if index < 0 {
				return seqValue(len(v.Urgencies))
			}
			if uint64(index) >= uint64(len(v.Urgencies)) {
				panic("invalid index")
			}
			return textValue(v.Urgencies[index])
		}
	case 12:
		v := &r.Images[row].Metadata
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
		v := &r.Images[row].Diagnostics[sub]
		switch field {
		case 1:
			return textValue(v.Code)
		case 2:
			return textValue(v.Message)
		}
	case 14:
		v := &r.AdvisorySources[row].Severities[sub]
		switch field {
		case 1:
			return textValue(v.Type)
		case 2:
			return textValue(v.Source)
		case 3:
			return textValue(v.Vector)
		}
	case 15:
		v := &r.AdvisorySources[row].References[sub]
		switch field {
		case 1:
			return textValue(v.Type)
		case 2:
			return textValue(v.URL)
		}
	case 16:
		v := &r.Fixes[row].Severities[sub]
		switch field {
		case 1:
			return textValue(v.Type)
		case 2:
			return textValue(v.Source)
		case 3:
			return textValue(v.Vector)
		}
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
