//go:build windows

package capture

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
)

// requireNpcap opens a live source or skips. Everything below needs a real
// pcap_t: these are the paths that cannot be reasoned about from a machine
// without the driver, which is exactly why they are worth running when one
// is present.
func requireNpcap(t *testing.T) Source {
	t.Helper()
	if _, err := loadWpcap(); err != nil {
		t.Skipf("Npcap is not installed: %v", err)
	}
	src, err := OpenLive("", LiveOptions{ReadTimeout: 200 * time.Millisecond})
	if err != nil {
		var perr *PermissionError
		if errors.As(err, &perr) {
			t.Skipf("Npcap is installed but restricted to Administrators: %v", err)
		}
		t.Skipf("no capturable interface: %v", err)
	}
	return src
}

// Close from one goroutine while Next is blocked in pcap_next_ex on another
// is what Ctrl-C does, and it used to be a use-after-free.
//
// A pcap_t is not thread-safe: pcap_close frees it and the buffer the
// in-flight read is filling. The bug does not reproduce on every attempt —
// it needs the close to land inside the read rather than between reads — so
// this repeats, and staggers the delay across the read timeout to move the
// window around.
func TestCloseDuringNextIsClean(t *testing.T) {
	const attempts = 40
	for i := 0; i < attempts; i++ {
		func() {
			src := requireNpcap(t)
			var (
				wg      sync.WaitGroup
				lastErr error
			)
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					_, _, err := src.Next()
					if err != nil {
						lastErr = err
						return
					}
				}
			}()

			// Sweep the close across the 200ms read timeout so it lands
			// inside pcap_next_ex, not only between calls.
			time.Sleep(time.Duration(i%20) * 10 * time.Millisecond)
			if err := src.Close(); err != nil {
				t.Fatalf("attempt %d: Close: %v", i, err)
			}
			wg.Wait()

			// Shutdown must be indistinguishable from exhaustion, or every
			// successful capture ends with a failure message and a non-zero
			// exit: pipeline.run and capture.Done both key on io.EOF.
			if !errors.Is(lastErr, io.EOF) {
				t.Fatalf("attempt %d: Next after Close = %v, want io.EOF", i, lastErr)
			}
			if !Done(lastErr) {
				t.Fatalf("attempt %d: capture.Done(%v) = false", i, lastErr)
			}
			// Close is idempotent; the second one must not double-free.
			if err := src.Close(); err != nil {
				t.Fatalf("attempt %d: second Close: %v", i, err)
			}
		}()
	}
}

// Ctrl-C on a silent interface must still stop promptly.
//
// Next does not return on a read timeout — it loops, because a timeout is
// not a packet — so on a quiet adapter it can sit inside pcap_next_ex
// indefinitely. Close has to take the handle lock to make freeing the
// pcap_t safe, which puts it behind exactly that call: if the read timeout
// did not bound it, the synchronisation that fixed the use-after-free would
// have replaced a crash on Ctrl-C with a hang on Ctrl-C.
//
// The bound is one read timeout, so this asserts against a generous
// multiple of it rather than a tight one.
func TestCloseIsPromptOnAQuietInterface(t *testing.T) {
	const readTimeout = 200 * time.Millisecond
	if _, err := loadWpcap(); err != nil {
		t.Skipf("Npcap is not installed: %v", err)
	}
	src, err := OpenLive("", LiveOptions{ReadTimeout: readTimeout})
	if err != nil {
		t.Skipf("no capturable interface: %v", err)
	}

	blocked := make(chan error, 1)
	go func() {
		for {
			if _, _, err := src.Next(); err != nil {
				blocked <- err
				return
			}
		}
	}()
	// Let the reader get inside pcap_next_ex rather than racing the open.
	time.Sleep(500 * time.Millisecond)

	start := time.Now()
	if err := src.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if waited := time.Since(start); waited > 10*readTimeout {
		t.Errorf("Close took %v, more than the %v read timeout that is meant to bound it",
			waited, readTimeout)
	}

	select {
	case err := <-blocked:
		if !errors.Is(err, io.EOF) {
			t.Errorf("Next after Close = %v, want io.EOF", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Next never returned after Close")
	}
}

// A capture that yields packets must yield sane ones. A wrong pcap_pkthdr
// layout does not crash — it shifts caplen and len by eight bytes — so the
// lengths are checked against the snaplen the handle was opened with, which
// is the invariant the layout assertions cannot reach.
func TestCapturedPacketsAreWellFormed(t *testing.T) {
	if _, err := loadWpcap(); err != nil {
		t.Skipf("Npcap is not installed: %v", err)
	}
	const snaplen = 65535
	src, err := OpenLive("", LiveOptions{Snaplen: snaplen, ReadTimeout: 200 * time.Millisecond})
	if err != nil {
		t.Skipf("no capturable interface: %v", err)
	}
	defer src.Close()

	type packet struct {
		data []byte
		ci   gopacket.CaptureInfo
	}
	got := make(chan packet, 1)
	go func() {
		for {
			data, ci, err := src.Next()
			if err != nil {
				return
			}
			select {
			case got <- packet{data, ci}:
			default:
			}
		}
	}()

	select {
	case p := <-got:
		if len(p.data) != p.ci.CaptureLength {
			t.Errorf("len(data) = %d but CaptureLength = %d", len(p.data), p.ci.CaptureLength)
		}
		if p.ci.CaptureLength <= 0 || p.ci.CaptureLength > snaplen {
			t.Errorf("CaptureLength = %d, want 1..%d", p.ci.CaptureLength, snaplen)
		}
		if p.ci.Length < p.ci.CaptureLength {
			t.Errorf("Length = %d is below CaptureLength = %d", p.ci.Length, p.ci.CaptureLength)
		}
		// A timestamp read through a wrong-width timeval lands in 1970 or
		// far in the future rather than near now.
		if d := time.Since(p.ci.Timestamp); d < -time.Minute || d > time.Hour {
			t.Errorf("timestamp %v is %v from now; struct timeval is being read wrongly",
				p.ci.Timestamp, d)
		}
	case <-time.After(20 * time.Second):
		t.Skip("no packets seen on the default interface within 20s")
	}
}

// The optional entry points, checked against a real DLL.
//
// Both are resolved with FindProc and ignored when absent, which means a
// rename or a build that omits them turns the corresponding option into a
// silent no-op rather than an error. BufferBytes is documented and
// defaulted, so it silently doing nothing is exactly the failure worth
// catching on a machine that has the driver.
func TestOptionalProcsResolve(t *testing.T) {
	w, err := loadWpcap()
	if err != nil {
		t.Skipf("Npcap is not installed: %v", err)
	}
	if w.setBuff == nil {
		t.Error("pcap_setbuff did not resolve; LiveOptions.BufferBytes is inert on this driver")
	}
	if w.setMinToCopy == nil {
		t.Error("pcap_setmintocopy did not resolve; a quiet interface will look hung")
	}
}
