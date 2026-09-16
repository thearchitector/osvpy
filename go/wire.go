package main

/*
#include <stdlib.h>
#include <stdint.h>
static void* report_realloc(void* p, size_t n) { return realloc(p, n); }
*/
import "C"

import (
	"encoding/json"
	"math"
	"runtime/cgo"
	"unsafe"

	"github.com/vmihailenco/msgpack/v5"
)

// Status codes are deliberately bounded and contain no dependency/credential
// text: 1 internal, 2 overflow, 3 allocation.
func guard(status *C.int) {
	if p := recover(); p != nil {
		*status = 1
		if s, ok := p.(string); ok {
			switch s {
			case "report_overflow":
				*status = 2
			case "report_allocation":
				*status = 3
			}
		}
	}
}

type nativeBatch struct {
	builder *batchBuilder
	req     request
}

//export osv_batch_begin
func osv_batch_begin(input *C.char, out *C.uintptr_t) (status C.int) {
	defer guard(&status)
	*out = 0
	var req request
	if err := json.Unmarshal([]byte(C.GoString(input)), &req); err != nil {
		panic(err)
	}
	scanMu.Lock()
	success := false
	defer func() {
		if !success {
			scanMu.Unlock()
		}
	}()
	*out = C.uintptr_t(cgo.NewHandle(&nativeBatch{newBuilder(), req}))
	success = true
	return 0
}

//export osv_batch_add
func osv_batch_add(handle C.uintptr_t, input *C.char, n C.size_t) (status C.int) {
	defer guard(&status)
	b := cgo.Handle(handle).Value().(*nativeBatch)
	req := b.req
	req.Image = string(unsafe.Slice((*byte)(unsafe.Pointer(input)), int(n)))
	resp := execute(req)
	b.builder.add(req, resp)
	return 0
}

//export osv_batch_abort
func osv_batch_abort(handle C.uintptr_t) (status C.int) {
	defer guard(&status)
	h := cgo.Handle(handle)
	b := h.Value().(*nativeBatch)
	b.builder = nil
	h.Delete()
	scanMu.Unlock()
	return 0
}

type directWriter struct {
	p           unsafe.Pointer
	n, capacity int
	// Optional per-writer allocator enables deterministic allocation-failure
	// tests without changing process-global allocation behavior.
	allocate func(unsafe.Pointer, int) unsafe.Pointer
}

func (w *directWriter) free() { C.free(w.p); w.p = nil }
func (w *directWriter) Write(b []byte) (int, error) {
	if uint64(w.n)+uint64(len(b)) > math.MaxUint32 {
		panic("report_overflow")
	}
	n := w.n + len(b)
	if n > w.capacity {
		capacity := max(n, min(max(w.capacity, 4096)*2, math.MaxUint32))
		var p unsafe.Pointer
		if w.allocate != nil {
			p = w.allocate(w.p, capacity)
		} else {
			p = C.report_realloc(w.p, C.size_t(capacity))
		}
		if p == nil {
			panic("report_allocation")
		}
		w.p = p
		w.capacity = capacity
	}
	copy(unsafe.Slice((*byte)(unsafe.Add(w.p, w.n)), len(b)), b)
	w.n = n
	return len(b), nil
}

// encodeReport streams MessagePack into the owned C allocation.
func encodeReport(w *directWriter, report reportStore) error {
	encoder := msgpack.NewEncoder(w)
	encoder.SetCustomStructTag("json")
	return encoder.Encode(report)
}

//export osv_batch_finish
func osv_batch_finish(handle C.uintptr_t, out *unsafe.Pointer, n *C.size_t) (status C.int) {
	defer guard(&status)
	*out = nil
	*n = 0
	w := &directWriter{}
	defer w.free()
	b := cgo.Handle(handle).Value().(*nativeBatch)
	report := b.builder.finish()
	if err := encodeReport(w, report); err != nil {
		return 1
	}
	p := C.report_realloc(w.p, C.size_t(w.n))
	if p == nil {
		panic("report_allocation")
	}
	w.p = p
	*out = w.p
	*n = C.size_t(w.n)
	w.p = nil
	return 0
}

//export osv_report_free
func osv_report_free(p unsafe.Pointer) { C.free(p) }
