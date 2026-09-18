package main

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	scalibrconfig "github.com/google/osv-scalibr/plugin/config"
)

func awaitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("operation deadlocked")
	}
}

func TestReorderAdmissionAndCancellation(t *testing.T) {
	for _, n := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			req := request{Workers: n}
			for i := range 20 {
				req.Inputs = append(req.Inputs, fmt.Sprint(i))
			}
			op := newOperation(req)
			admitted := make(chan string, 20)
			var active atomic.Int32
			go op.run(func(ctx context.Context, req request, _ *scalibrconfig.PluginConfig) response {
				active.Add(1)
				defer active.Add(-1)
				admitted <- req.Image
				if req.Image == "0" {
					<-ctx.Done()
				}
				return response{}
			})
			for range n {
				select {
				case <-admitted:
				case <-time.After(10 * time.Second):
					t.Fatal("workers not admitted")
				}
			}
			op.cancel()
			awaitDone(t, op.done)
			if op.wait() != 4 || active.Load() != 0 {
				t.Fatal("cancellation did not join workers")
			}
			if len(admitted) != 0 {
				t.Fatal("admitted past the reorder window")
			}
		})
	}
}

func TestOperationInputOrder(t *testing.T) {
	req := request{Workers: 4, Inputs: []string{"0", "1", "2", "3", "4"}}
	op := newOperation(req)
	laterDone := make(chan struct{})
	go op.run(func(ctx context.Context, req request, _ *scalibrconfig.PluginConfig) response {
		if req.Image == "0" {
			<-laterDone
		}
		if req.Image == "3" {
			close(laterDone)
		}
		return response{}
	})
	awaitDone(t, op.done)
	if op.wait() != 0 {
		t.Fatal(op.wait())
	}
	for i, im := range op.report.Images {
		if im.Requested != fmt.Sprint(i) {
			t.Fatal("out-of-order merge")
		}
	}
}

func TestCancelBeforeStart(t *testing.T) {
	op := newOperation(request{Workers: 1, Inputs: []string{"never"}})
	op.cancel()
	op.start()
	awaitDone(t, op.done)
	if op.wait() != 4 {
		t.Fatal("pending cancellation lost")
	}
	op.release()
}

func TestWorkerPanicJoinsSiblings(t *testing.T) {
	op := newOperation(request{Workers: 2, Inputs: []string{"panic", "blocked"}})
	go op.run(func(ctx context.Context, req request, _ *scalibrconfig.PluginConfig) response {
		if req.Image == "panic" {
			panic("test panic")
		}
		<-ctx.Done()
		return response{}
	})
	awaitDone(t, op.done)
	if op.wait() != 1 {
		t.Fatal("worker panic lost")
	}
}
