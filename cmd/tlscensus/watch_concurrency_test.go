package main

import (
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/connectedinformation/tlscensus/internal/assemble"
	"github.com/connectedinformation/tlscensus/internal/capture"
	"github.com/connectedinformation/tlscensus/internal/inventory"
)

// concurrentPcap holds connections that never close, so they are released by
// the idle sweep rather than by a FIN — which is what these tests need.
const concurrentPcap = "../../testdata/concurrent.pcap"

func feed(t *testing.T, p *pipeline, path string) {
	t.Helper()
	src, err := capture.OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	for {
		data, ci, err := src.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		p.packet(data, ci, src.LinkType())
	}
}

// A sweep must not deliver records while holding the assembler lock.
//
// watch serialises its writers on an output mutex, and the sweep runs on its
// own goroutine. If the sweep delivered from inside the assembler call, the
// writer would take the output lock beneath the assembler lock — and when the
// sweep itself already held the output lock, as it once did, a mutex that is
// not reentrant deadlocks the moment the idle sweep emits its first flow.
// Every connection here stays open, so the sweep is what emits them.
func TestFlushDeliversOutsideAssemblerLock(t *testing.T) {
	var mu sync.Mutex
	var delivered atomic.Int64
	p := newPipeline(assemble.Options{}, true, func(r *inventory.Record) {
		mu.Lock()
		defer mu.Unlock()
		delivered.Add(1)
	})

	feed(t, p, concurrentPcap)
	if n := delivered.Load(); n != 0 {
		t.Fatalf("%d records emitted before the sweep; these connections never close", n)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		p.flushOlderThan(time.Now().Add(24 * time.Hour))
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("sweep blocked after delivering %d record(s); "+
			"records are being delivered under the assembler lock", delivered.Load())
	}
	if n := delivered.Load(); n != 12 {
		t.Errorf("sweep delivered %d records, want 12", n)
	}
}

// The capture loop and the sweep must not touch the assembler at once.
//
// assemble.Assembler is not safe for concurrent use, and live capture drives
// it from both. Only -race can see this, and only if something exercises the
// two paths together, which no test of watch itself does.
func TestPacketAndFlushAreSerialised(t *testing.T) {
	var mu sync.Mutex
	p := newPipeline(assemble.Options{}, true, func(r *inventory.Record) {
		mu.Lock()
		defer mu.Unlock()
	})

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				p.flushOlderThan(time.Now().Add(-assemble.DefaultCloseTimeout))
			}
		}
	}()

	feed(t, p, concurrentPcap)
	feed(t, p, "../../testdata/sample.pcap")

	close(stop)
	wg.Wait()

	if rep := p.finish([]string{"test"}, 5, false); rep == nil {
		t.Fatal("finish returned nil")
	}
}
