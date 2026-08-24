//go:build darwin

package capture

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// bpfRecord builds one kernel BPF record: header, payload, alignment pad.
// hdrLen defaults to the struct size but can be inflated to mimic a kernel
// that pads the header differently.
func bpfRecord(payload []byte, sec, usec int32, dataLen int, hdrLen int) []byte {
	if hdrLen == 0 {
		hdrLen = bpfHdrLen
	}
	if dataLen == 0 {
		dataLen = len(payload)
	}
	e := binary.NativeEndian
	rec := make([]byte, hdrLen)
	e.PutUint32(rec[0:4], uint32(sec))
	e.PutUint32(rec[4:8], uint32(usec))
	e.PutUint32(rec[8:12], uint32(len(payload)))
	e.PutUint32(rec[12:16], uint32(dataLen))
	e.PutUint16(rec[16:18], uint16(hdrLen))
	rec = append(rec, payload...)
	for len(rec) < bpfWordAlign(len(rec)) {
		rec = append(rec, 0)
	}
	return rec
}

func TestNextBPFPacketSingle(t *testing.T) {
	payload := []byte("the quick brown fox")
	buf := bpfRecord(payload, 1750000000, 123456, 42, 0)

	data, ci, rest, err := nextBPFPacket(buf)
	if err != nil {
		t.Fatalf("nextBPFPacket: %v", err)
	}
	if !bytes.Equal(data, payload) {
		t.Errorf("data = %q, want %q", data, payload)
	}
	if ci.CaptureLength != len(payload) {
		t.Errorf("CaptureLength = %d, want %d", ci.CaptureLength, len(payload))
	}
	// Length is the original wire length, which exceeds CaptureLength when
	// the snaplen truncated the packet. Conflating the two would silently
	// misreport every truncated capture.
	if ci.Length != 42 {
		t.Errorf("Length = %d, want 42", ci.Length)
	}
	want := time.Unix(1750000000, 123456*1000)
	if !ci.Timestamp.Equal(want) {
		t.Errorf("Timestamp = %v, want %v", ci.Timestamp, want)
	}
	if rest != nil {
		t.Errorf("rest = %d bytes, want none", len(rest))
	}
}

// A single read() returns many packets back to back, each padded so the next
// header lands word-aligned. Getting the stride wrong desynchronises the
// whole buffer, which looks like random corruption rather than an off-by-one.
func TestNextBPFPacketMultiple(t *testing.T) {
	payloads := [][]byte{
		[]byte("a"),                 // 1 byte: needs 3 bytes of padding
		[]byte("bb"),                // 2: needs 2
		[]byte("ccc"),               // 3: needs 1
		[]byte("dddd"),              // 4: already aligned
		bytes.Repeat([]byte{7}, 97), // odd length
	}
	var buf []byte
	for i, p := range payloads {
		buf = append(buf, bpfRecord(p, int32(1750000000+i), 0, 0, 0)...)
	}

	var got [][]byte
	rest := buf
	for len(rest) > 0 {
		data, ci, next, err := nextBPFPacket(rest)
		if err != nil {
			t.Fatalf("packet %d: %v", len(got), err)
		}
		if ci.CaptureLength != len(data) {
			t.Errorf("packet %d: CaptureLength = %d, len(data) = %d",
				len(got), ci.CaptureLength, len(data))
		}
		got = append(got, bytes.Clone(data))
		rest = next
	}

	if len(got) != len(payloads) {
		t.Fatalf("read %d packets, want %d", len(got), len(payloads))
	}
	for i := range payloads {
		if !bytes.Equal(got[i], payloads[i]) {
			t.Errorf("packet %d = %q, want %q", i, got[i], payloads[i])
		}
	}
}

// bh_hdrlen is authoritative: the kernel may pad the header beyond the
// struct size. Computing the data offset from sizeof would work on one
// architecture and quietly corrupt every packet on another.
// The value macOS actually puts in bh_hdrlen is 18 — the unpadded field
// size — not sizeof(struct bpf_hdr), which is 20. Rejecting 18 as too short
// drops every packet the kernel delivers.
//
// The original test could not catch this: bpfRecord defaulted bh_hdrlen to
// the same constant the parser validated against, so the oracle agreed with
// the bug. Each real-world value is now asserted explicitly.
func TestNextBPFPacketRealHeaderLengths(t *testing.T) {
	payload := []byte("a packet the kernel actually delivered")
	for _, hdrLen := range []int{18, 20, 24} {
		buf := bpfRecord(payload, 1, 0, 0, hdrLen)
		data, ci, _, err := nextBPFPacket(buf)
		if err != nil {
			t.Errorf("bh_hdrlen=%d: %v", hdrLen, err)
			continue
		}
		if !bytes.Equal(data, payload) {
			t.Errorf("bh_hdrlen=%d: data = %q, want %q", hdrLen, data, payload)
		}
		if ci.CaptureLength != len(payload) {
			t.Errorf("bh_hdrlen=%d: CaptureLength = %d, want %d",
				hdrLen, ci.CaptureLength, len(payload))
		}
	}
}

func TestNextBPFPacketHonoursHeaderLength(t *testing.T) {
	payload := []byte("payload after a padded header")
	buf := bpfRecord(payload, 1, 0, 0, bpfHdrLen+12)

	data, _, _, err := nextBPFPacket(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, payload) {
		t.Errorf("data = %q, want %q", data, payload)
	}
}

// The tail of a read buffer is routinely a partial record. That is normal
// input, not corruption, and must not panic or over-read.
func TestNextBPFPacketRejectsMalformed(t *testing.T) {
	full := bpfRecord([]byte("0123456789abcdef"), 1, 0, 0, 0)
	e := binary.NativeEndian

	shortHdr := full[:bpfHdrLen-1]

	capTooLong := bytes.Clone(full)
	e.PutUint32(capTooLong[8:12], 1<<20) // caplen far past the buffer

	hdrTooShort := bytes.Clone(full)
	e.PutUint16(hdrTooShort[16:18], 12) // hdrlen below the field size

	hdrHuge := bytes.Clone(full)
	e.PutUint16(hdrHuge[16:18], 0xffff)

	for name, b := range map[string][]byte{
		"empty":             nil,
		"short header":      shortHdr,
		"caplen overruns":   capTooLong,
		"hdrlen too small":  hdrTooShort,
		"hdrlen overruns":   hdrHuge,
		"truncated payload": full[:bpfHdrLen+4],
	} {
		data, _, rest, err := nextBPFPacket(b)
		if err == nil {
			t.Errorf("%s: expected an error, got %d bytes", name, len(data))
		}
		if rest != nil {
			t.Errorf("%s: rest should be nil on error", name)
		}
	}
}

func TestBPFWordAlign(t *testing.T) {
	for in, want := range map[int]int{0: 0, 1: 4, 2: 4, 3: 4, 4: 4, 5: 8, 20: 20, 21: 24} {
		if got := bpfWordAlign(in); got != want {
			t.Errorf("bpfWordAlign(%d) = %d, want %d", in, got, want)
		}
	}
}
