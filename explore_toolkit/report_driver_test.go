package main

// Instrumentation adapter, copied into an isolated bridge module by reports.py.
// It is not part of the behavioral suite and imposes no performance budgets.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unsafe"
)

func TestExploreReports(t *testing.T) {
	var spec struct {
		Inputs      []string
		Output      string
		Independent bool
	}
	readJSON := func(path string, value any) {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, value); err != nil {
			t.Fatal(err)
		}
	}
	readJSON(os.Getenv("OSVPY_EXPLORE_SPEC"), &spec)
	runtime.GC()
	var base, sample runtime.MemStats
	runtime.ReadMemStats(&base)
	peak := base.HeapAlloc
	checkpoint := func() {
		runtime.ReadMemStats(&sample)
		peak = max(peak, sample.HeapAlloc)
	}
	var construction, encoding time.Duration
	maxC := 0
	build := newBuilder()
	emit := func(index int) {
		start := time.Now()
		report := build.finish()
		construction += time.Since(start)
		checkpoint()
		writer := &directWriter{}
		defer writer.free()
		start = time.Now()
		if err := encodeReport(writer, report); err != nil {
			t.Fatal(err)
		}
		encoding += time.Since(start)
		maxC = max(maxC, writer.capacity)
		path := filepath.Join(spec.Output, fmt.Sprintf("report-%d.msgpack", index))
		if err := os.WriteFile(path, unsafe.Slice((*byte)(writer.p), writer.n), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for index, path := range spec.Inputs {
		var input struct {
			Request request
			response
		}
		readJSON(path, &input)
		start := time.Now()
		build.add(input.Request, input.response)
		construction += time.Since(start)
		checkpoint()
		if spec.Independent {
			emit(index)
			build = newBuilder()
		}
	}
	if !spec.Independent {
		emit(0)
	}
	build = nil
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	stats := map[string]any{
		"construction_seconds": construction.Seconds(), "encode_seconds": encoding.Seconds(),
		"sampled_go_peak_bytes": int64(peak) - int64(base.HeapAlloc),
		"post_release_go_bytes": int64(after.HeapAlloc) - int64(base.HeapAlloc),
		"max_c_capacity_bytes":  maxC,
	}
	raw, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spec.Output, "native.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
}
