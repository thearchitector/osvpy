package main

/*
#include <stdlib.h>
#include <stdint.h>
typedef void (*sink_fn)(const void*, size_t);
static void deliver(sink_fn sink, const void *p, size_t n) { sink(p, n); }
*/
import "C"

import (
	"encoding/json"
	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"runtime"
	"runtime/cgo"
	"unsafe"
)

type fullResult struct {
	models.VulnerabilityResults
	Image    string          `json:"image"`
	Metadata json.RawMessage `json:"metadata"`
}
type envelope struct {
	ABIVersion int            `json:"abi_version"`
	OK         bool           `json:"ok"`
	Result     *fullResult    `json:"result,omitempty"`
	Report     *compactReport `json:"report,omitempty"`
}
type compactReport struct {
	Image           string           `json:"image"`
	Metadata        json.RawMessage  `json:"metadata"`
	Vulnerabilities []summary        `json:"vulnerabilities"`
	Packages        []packageSummary `json:"packages"`
}
type summary struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Severity struct {
		Score  *float64 `json:"score"`
		Rating string   `json:"rating"`
	} `json:"severity"`
	Packages []string `json:"packages"`
}
type packageSummary struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Version         string `json:"installed_version"`
	Ecosystem       string `json:"ecosystem"`
	Vulnerabilities []struct {
		ID            string   `json:"id"`
		FixedVersions []string `json:"fixed_versions"`
	} `json:"vulnerabilities"`
}

var value envelope

type advisoryView struct{ *osvschema.Vulnerability }

func (a advisoryView) MarshalJSON() ([]byte, error) { return protojson.Marshal(a.Vulnerability) }

type packageAlias models.PackageVulns
type packageView struct {
	*packageAlias
	Vulnerabilities []advisoryView `json:"vulnerabilities,omitempty"`
}
type sourceAlias models.PackageSource
type sourceView struct {
	*sourceAlias
	Packages []packageView `json:"packages"`
}
type fullView struct {
	*fullResult
	Results []sourceView `json:"results"`
}

func directView() any {
	view := fullView{fullResult: value.Result}
	for i := range value.Result.Results {
		source := &value.Result.Results[i]
		sv := sourceView{sourceAlias: (*sourceAlias)(source)}
		for j := range source.Packages {
			pkg := &source.Packages[j]
			pv := packageView{packageAlias: (*packageAlias)(pkg)}
			for _, adv := range pkg.Vulnerabilities {
				pv.Vulnerabilities = append(pv.Vulnerabilities, advisoryView{adv})
			}
			sv.Packages = append(sv.Packages, pv)
		}
		view.Results = append(view.Results, sv)
	}
	return struct {
		ABIVersion int      `json:"abi_version"`
		OK         bool     `json:"ok"`
		Result     fullView `json:"result"`
	}{value.ABIVersion, value.OK, view}
}

//export lab_load
func lab_load(p *C.char, n C.int) C.int {
	if err := json.Unmarshal(C.GoBytes(unsafe.Pointer(p), n), &value); err != nil {
		return 1
	}
	runtime.GC()
	return 0
}

type cWriter struct {
	p unsafe.Pointer
	n int
}

func (w *cWriter) Write(b []byte) (int, error) {
	if w.p != nil {
		panic("encoder unexpectedly wrote twice")
	}
	w.p = C.CBytes(b)
	w.n = len(b)
	return len(b), nil
}

type callbackWriter struct{ sink C.sink_fn }

func (w callbackWriter) Write(b []byte) (int, error) {
	C.deliver(w.sink, unsafe.Pointer(unsafe.SliceData(b)), C.size_t(len(b)))
	return len(b), nil
}

//export lab_encode
func lab_encode(mode C.int, length *C.size_t) unsafe.Pointer {
	if mode == 2 {
		w := &cWriter{}
		if err := json.NewEncoder(w).Encode(value); err != nil {
			panic(err)
		}
		*length = C.size_t(w.n)
		return w.p
	}
	b, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	*length = C.size_t(len(b))
	if mode == 0 {
		return unsafe.Pointer(C.CString(string(b)))
	}
	return C.CBytes(b)
}

//export lab_callback
func lab_callback(mode C.int, sink C.sink_fn) {
	var v any = value
	if mode == 4 {
		v = directView()
	}
	if err := json.NewEncoder(callbackWriter{sink}).Encode(v); err != nil {
		panic(err)
	}
}

//export lab_free
func lab_free(p unsafe.Pointer) { C.free(p) }

//export lab_total_alloc
func lab_total_alloc() C.ulonglong {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return C.ulonglong(m.TotalAlloc)
}

type pinnedResponse struct {
	bytes []byte
	pin   runtime.Pinner
}

//export lab_pinned
func lab_pinned(out *unsafe.Pointer, length *C.size_t) C.uintptr_t {
	b, err := json.Marshal(directView())
	if err != nil {
		panic(err)
	}
	owner := &pinnedResponse{bytes: b}
	owner.pin.Pin(unsafe.SliceData(b))
	*out = unsafe.Pointer(unsafe.SliceData(b))
	*length = C.size_t(len(b))
	return C.uintptr_t(cgo.NewHandle(owner))
}

//export lab_unpin
func lab_unpin(id C.uintptr_t) {
	h := cgo.Handle(id)
	h.Value().(*pinnedResponse).pin.Unpin()
	h.Delete()
}

//export lab_report_handle
func lab_report_handle() C.uintptr_t { return C.uintptr_t(cgo.NewHandle(value.Result)) }

//export lab_report_count
func lab_report_count(id C.uintptr_t) C.size_t {
	result := cgo.Handle(id).Value().(*fullResult)
	n := 0
	for _, s := range result.Results {
		n += len(s.Packages)
	}
	return C.size_t(n)
}

//export lab_report_details
func lab_report_details(id C.uintptr_t, source C.int, pkg C.int, sink C.sink_fn) {
	result := cgo.Handle(id).Value().(*fullResult)
	text := result.Results[int(source)].Packages[int(pkg)].Vulnerabilities[0].GetDetails()
	C.deliver(sink, unsafe.Pointer(unsafe.StringData(text)), C.size_t(len(text)))
}

//export lab_report_release
func lab_report_release(id C.uintptr_t) { cgo.Handle(id).Delete() }

//export lab_detach_and_gc
func lab_detach_and_gc() { value = envelope{}; runtime.GC() }

//export lab_gc
func lab_gc() { runtime.GC() }

//export lab_heap
func lab_heap() C.ulonglong {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return C.ulonglong(m.HeapAlloc)
}

func main() {}
