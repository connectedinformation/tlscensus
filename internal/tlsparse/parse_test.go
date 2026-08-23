package tlsparse

import (
	"slices"
	"testing"
)

// pqcSpec is a Chrome-shaped post-quantum ClientHello: hybrid key share
// first, classical second, GREASE throughout.
func pqcSpec() chSpec {
	return chSpec{
		Ciphers:           []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc030},
		SNI:               "example.com",
		ALPN:              []string{"h2", "http/1.1"},
		SupportedVersions: []uint16{0x0304, 0x0303},
		Groups:            []uint16{0x11ec, 29, 23, 24},
		KeyShares:         []uint16{0x11ec, 29},
		SigAlgs:           []uint16{0x0403, 0x0804, 0x0401, 0x0503},
	}
}

func TestParseClientHello(t *testing.T) {
	ch, err := ParseClientHello(buildClientHello(pqcSpec()))
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}

	if ch.ServerName != "example.com" {
		t.Errorf("ServerName = %q, want example.com", ch.ServerName)
	}
	if got, want := ch.ALPN, []string{"h2", "http/1.1"}; !slices.Equal(got, want) {
		t.Errorf("ALPN = %v, want %v", got, want)
	}
	if got, want := ch.CipherSuites, []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc030}; !slices.Equal(got, want) {
		t.Errorf("CipherSuites = %#04x, want %#04x", got, want)
	}
	if !ch.GREASE {
		t.Error("GREASE = false, want true")
	}
	if got, want := ch.SupportedGroups, []uint16{0x11ec, 29, 23, 24}; !slices.Equal(got, want) {
		t.Errorf("SupportedGroups = %#04x, want %#04x", got, want)
	}
	// The field the whole tool exists to report.
	if got, want := ch.KeyShareGroups, []uint16{0x11ec, 29}; !slices.Equal(got, want) {
		t.Errorf("KeyShareGroups = %#04x, want %#04x", got, want)
	}
	if got, want := ch.SupportedVersions, []uint16{0x0304, 0x0303}; !slices.Equal(got, want) {
		t.Errorf("SupportedVersions = %#04x, want %#04x", got, want)
	}
	if got := ch.NegotiatedVersion(); got != 0x0304 {
		t.Errorf("NegotiatedVersion = %#04x, want 0x0304", got)
	}
	if ch.Truncated {
		t.Error("Truncated = true on a complete message")
	}
	// GREASE must not survive into any list, including extensions.
	for _, e := range ch.Extensions {
		if IsGREASE(e) {
			t.Errorf("GREASE extension %#04x leaked into Extensions", e)
		}
	}
}

// A supported_groups entry that never gets a key share is the difference
// between "would accept post-quantum" and "is actually using it".
func TestKeyShareDistinctFromSupportedGroups(t *testing.T) {
	s := pqcSpec()
	s.Groups = []uint16{0x11ec, 29}
	s.KeyShares = []uint16{29} // advertises PQ, only bets on classical
	ch, err := ParseClientHello(buildClientHello(s))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(ch.SupportedGroups, 0x11ec) {
		t.Error("SupportedGroups lost the PQ group")
	}
	if slices.Contains(ch.KeyShareGroups, 0x11ec) {
		t.Error("KeyShareGroups gained a group that was never shared")
	}
}

// A post-quantum ClientHello exceeds one TCP segment, so the record and
// handshake layers must both survive fragmentation. This is the failure mode
// that silently drops exactly the traffic a PQ inventory is looking for.
func TestFragmentedClientHello(t *testing.T) {
	body := handshakeMsg(HandshakeClientHello, buildClientHello(pqcSpec()))
	if len(body) < 1400 {
		t.Fatalf("synthetic PQ ClientHello is only %d bytes; too small to exercise fragmentation", len(body))
	}

	for _, chunk := range []int{len(body), 1024, 512, 64, 1} {
		stream := records(RecordHandshake, body, chunk)
		ch, err := FindClientHello(stream)
		if err != nil {
			t.Fatalf("chunk=%d: %v", chunk, err)
		}
		if ch == nil {
			t.Fatalf("chunk=%d: no ClientHello found", chunk)
		}
		if ch.ServerName != "example.com" {
			t.Errorf("chunk=%d: ServerName = %q", chunk, ch.ServerName)
		}
		if got, want := ch.KeyShareGroups, []uint16{0x11ec, 29}; !slices.Equal(got, want) {
			t.Errorf("chunk=%d: KeyShareGroups = %#04x, want %#04x", chunk, got, want)
		}
	}
}

// A capture keeps a bounded prefix, so a truncated hello is normal input,
// not an error. Everything decoded before the cut must still be reported.
func TestTruncatedClientHelloIsPartial(t *testing.T) {
	body := handshakeMsg(HandshakeClientHello, buildClientHello(pqcSpec()))
	full := records(RecordHandshake, body, 0)

	for _, keep := range []int{len(full) / 2, len(full) - 1, 200, 60} {
		if keep >= len(full) || keep < 6 {
			continue
		}
		// Must not panic, must not hang, must not invent data.
		ch, err := FindClientHello(full[:keep])
		if err != nil && err != ErrNotTLS {
			t.Fatalf("keep=%d: unexpected error %v", keep, err)
		}
		_ = ch
	}
}

func TestClientHelloWithoutExtensions(t *testing.T) {
	ch, err := ParseClientHello(buildClientHello(chSpec{
		LegacyVersion:  0x0301,
		Ciphers:        []uint16{0x002f, 0x0035},
		OmitExtensions: true,
	}))
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if got := ch.NegotiatedVersion(); got != 0x0301 {
		t.Errorf("NegotiatedVersion = %#04x, want 0x0301", got)
	}
	if len(ch.Extensions) != 0 {
		t.Errorf("Extensions = %v, want none", ch.Extensions)
	}
}

func TestECH(t *testing.T) {
	s := pqcSpec()
	s.ECH = true
	s.SNI = "cloudflare-ech.com" // the public outer name
	ch, err := ParseClientHello(buildClientHello(s))
	if err != nil {
		t.Fatal(err)
	}
	if ch.ECH == nil {
		t.Fatal("ECH = nil, want populated")
	}
	if !ch.ECH.Outer {
		t.Error("ECH.Outer = false, want true")
	}
	if ch.ECH.ConfigID != 7 {
		t.Errorf("ECH.ConfigID = %d, want 7", ch.ECH.ConfigID)
	}
}

func TestParseServerHelloTLS13(t *testing.T) {
	body := handshakeMsg(HandshakeServerHello, buildServerHello(shSpec{
		Cipher:          0x1301,
		SelectedVersion: 0x0304,
		Group:           0x11ec,
		ALPN:            "h2",
	}))
	sh, err := FindServerHello(records(RecordHandshake, body, 0))
	if err != nil {
		t.Fatal(err)
	}
	if sh == nil {
		t.Fatal("no ServerHello")
	}
	// A TLS 1.3 server pins legacy_version to 1.2; supported_versions wins.
	if sh.LegacyVersion != 0x0303 {
		t.Errorf("LegacyVersion = %#04x, want 0x0303", sh.LegacyVersion)
	}
	if got := sh.NegotiatedVersion(); got != 0x0304 {
		t.Errorf("NegotiatedVersion = %#04x, want 0x0304", got)
	}
	if sh.CipherSuite != 0x1301 {
		t.Errorf("CipherSuite = %#04x, want 0x1301", sh.CipherSuite)
	}
	if sh.Group != 0x11ec || sh.GroupSource != GroupSourceKeyShare {
		t.Errorf("Group = %#04x from %q, want 0x11ec from key_share", sh.Group, sh.GroupSource)
	}
	if sh.SelectedALPN != "h2" {
		t.Errorf("SelectedALPN = %q, want h2", sh.SelectedALPN)
	}
}

// TLS 1.2 states its group only in ServerKeyExchange. Without that, every
// 1.2 flow would report an unknown group.
func TestServerKeyExchangeGroup(t *testing.T) {
	var stream []byte
	stream = append(stream, handshakeMsg(HandshakeServerHello, buildServerHello(shSpec{
		Cipher: 0xc02f, // ECDHE_RSA_WITH_AES_128_GCM_SHA256
	}))...)
	ske := append([]byte{3, 0x00, 0x1d}, make([]byte, 32)...) // named_curve x25519
	stream = append(stream, handshakeMsg(HandshakeServerKeyExchange, ske)...)

	sh, err := FindServerHello(records(RecordHandshake, stream, 0))
	if err != nil {
		t.Fatal(err)
	}
	if sh.Group != 29 || sh.GroupSource != GroupSourceServerKeyExchange {
		t.Errorf("Group = %#04x from %q, want 0x001d from server_key_exchange", sh.Group, sh.GroupSource)
	}
	if got := sh.NegotiatedVersion(); got != 0x0303 {
		t.Errorf("NegotiatedVersion = %#04x, want 0x0303", got)
	}
}

// After a HelloRetryRequest the real ServerHello follows in the clear; the
// scan must return the latter, not stop at the former.
func TestHelloRetryRequestThenServerHello(t *testing.T) {
	var stream []byte
	stream = append(stream, handshakeMsg(HandshakeServerHello, buildServerHello(shSpec{
		Cipher: 0x1301, SelectedVersion: 0x0304, Group: 23, HelloRetry: true,
	}))...)
	stream = append(stream, handshakeMsg(HandshakeServerHello, buildServerHello(shSpec{
		Cipher: 0x1302, SelectedVersion: 0x0304, Group: 23,
	}))...)

	sh, err := FindServerHello(records(RecordHandshake, stream, 0))
	if err != nil {
		t.Fatal(err)
	}
	if sh.IsHelloRetryRequest {
		t.Error("returned the HelloRetryRequest instead of the ServerHello")
	}
	if sh.CipherSuite != 0x1302 {
		t.Errorf("CipherSuite = %#04x, want 0x1302", sh.CipherSuite)
	}
}

// A lone HRR is still worth reporting when nothing follows it in the
// captured prefix.
func TestHelloRetryRequestAlone(t *testing.T) {
	body := handshakeMsg(HandshakeServerHello, buildServerHello(shSpec{
		Cipher: 0x1301, SelectedVersion: 0x0304, Group: 0x11ec, HelloRetry: true,
	}))
	sh, err := FindServerHello(records(RecordHandshake, body, 0))
	if err != nil {
		t.Fatal(err)
	}
	if sh == nil || !sh.IsHelloRetryRequest {
		t.Fatal("want a HelloRetryRequest")
	}
	if sh.Group != 0x11ec {
		t.Errorf("Group = %#04x, want 0x11ec", sh.Group)
	}
}

func TestNotTLS(t *testing.T) {
	for name, b := range map[string][]byte{
		"http":  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		"ssh":   []byte("SSH-2.0-OpenSSH_9.6\r\n"),
		"zeros": make([]byte, 64),
		"appdata": append([]byte{RecordApplicationData, 0x03, 0x03, 0x00, 0x10},
			make([]byte, 16)...),
	} {
		if _, err := FindClientHello(b); err != ErrNotTLS {
			t.Errorf("%s: err = %v, want ErrNotTLS", name, err)
		}
	}
}

// Reading stops at the first application-data record: under TLS 1.3 every
// handshake message after ServerHello lives inside those, encrypted.
func TestStopsAtApplicationData(t *testing.T) {
	var stream []byte
	stream = append(stream, records(RecordHandshake,
		handshakeMsg(HandshakeServerHello, buildServerHello(shSpec{
			Cipher: 0x1301, SelectedVersion: 0x0304, Group: 29,
		})), 0)...)
	stream = append(stream, RecordChangeCipherSpec, 0x03, 0x03, 0x00, 0x01, 0x01)
	stream = append(stream, RecordApplicationData, 0x03, 0x03, 0x00, 0x20)
	stream = append(stream, make([]byte, 32)...)

	msgs, err := HandshakeMessages(stream)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[0].Type != HandshakeServerHello {
		t.Fatalf("got %d messages, want exactly one ServerHello", len(msgs))
	}
}
