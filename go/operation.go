package main

import (
	"context"
	"sync"

	scalibrconfig "github.com/google/osv-scalibr/plugin/config"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
)

type operation struct {
	ctx      context.Context
	cancel   context.CancelFunc
	req      request
	done     chan struct{}
	mu       sync.Mutex
	started  bool
	finished bool
	report   reportStore
	status   int
}

func newOperation(req request) *operation {
	ctx, cancel := context.WithCancel(context.Background())
	return &operation{ctx: ctx, cancel: cancel, req: req, done: make(chan struct{})}
}

func panicStatus(value any) int {
	switch value {
	case "report_overflow":
		return 2
	case "report_allocation":
		return 3
	case context.Canceled:
		return 4
	default:
		return 1
	}
}

func (op *operation) start() {
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.started {
		return
	}
	op.started = true
	go op.run(executeContext)
}

type scanFunc func(context.Context, request, *scalibrconfig.PluginConfig) response

func (op *operation) run(scan scanFunc) {
	defer close(op.done)
	defer func() {
		if p := recover(); p != nil {
			op.status = panicStatus(p)
			op.report = reportStore{}
		}
	}()
	checkContext(op.ctx)
	builder := newBuilder()
	builder.ctx = op.ctx
	type result struct {
		index      int
		req        request
		response   response
		panicValue any
	}
	count := min(op.req.Workers, len(op.req.Inputs))
	jobs := make(chan int, count)
	results := make(chan result, count)
	ctx, cancel := context.WithCancel(op.ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); close(jobs); workers.Wait() }()
	for range count {
		workers.Go(func() {
			cf, cleanup := osvscanner.SetupClientFactories(nil, nil, "osvpy/0.1.0")
			defer cleanup()
			for {
				select {
				case <-ctx.Done():
					return
				case j, ok := <-jobs:
					if !ok {
						return
					}
					req := op.req
					req.Image = req.Inputs[j]
					r := result{index: j, req: req}
					func() {
						defer func() {
							r.panicValue = recover()
						}()
						checkContext(ctx)
						r.response = scan(ctx, req, &scalibrconfig.PluginConfig{ClientFactories: cf})
					}()
					select {
					case results <- r:
					case <-ctx.Done():
						return
					}
					r = result{}
				}
			}
		})
	}
	admitted, merged := 0, 0
	pending := make(map[int]pendingImage, count)
	admit := func() {
		checkContext(op.ctx)
		jobs <- admitted
		admitted++
	}
	for admitted < count {
		admit()
	}
	for merged < len(op.req.Inputs) {
		select {
		case <-op.ctx.Done():
			checkContext(op.ctx)
		case r := <-results:
			checkContext(op.ctx)
			if r.panicValue != nil {
				panic(r.panicValue)
			}
			if r.index == merged {
				builder.add(r.req, r.response)
				r = result{}
				merged++
				if admitted < len(op.req.Inputs) {
					admit()
				}
			} else {
				facts := pendingImage{}
				facts.image = projectImage(op.ctx, r.req, r.response, &facts)
				pending[r.index] = facts
			}
		}
		for {
			r, ok := pending[merged]
			if !ok {
				break
			}
			delete(pending, merged)
			checkContext(op.ctx)
			builder.merge(r)
			r = pendingImage{}
			merged++
			if admitted < len(op.req.Inputs) {
				admit()
			}
		}
	}
	op.report = builder.finish()
	checkContext(op.ctx)
}

func (op *operation) wait() int {
	<-op.done
	if op.ctx.Err() != nil {
		return panicStatus(op.ctx.Err())
	}
	return op.status
}

func (op *operation) release() {
	op.cancel()
	op.mu.Lock()
	started := op.started
	op.mu.Unlock()
	if started {
		<-op.done
	}
	op.report = reportStore{}
}

// finish transfers even an empty result exactly once. The operation is owned by
// one executor; cancellation is the only concurrent control operation.
func (op *operation) finish() (*reportStore, int) {
	if status := op.wait(); status != 0 {
		return nil, status
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.finished {
		return nil, 1
	}
	op.finished = true
	report := op.report
	op.report = reportStore{}
	op.req = request{}
	return &report, 0
}
