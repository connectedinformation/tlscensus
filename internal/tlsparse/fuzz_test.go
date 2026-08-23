package tlsparse

import "testing"

// The parser reads attacker-controlled bytes inside a privileged process.
// It must never panic, never hang, and never allocate proportionally to a
// declared length rather than to the bytes actually present.
//
// Run locally with:
//
//	go test ./internal/tlsparse -run=Fuzz -fuzz=FuzzParseStream -fuzztime=60s
//
// This is also the entry point registered with OSS-Fuzz; see SECURITY.md.
func FuzzParseStream(f *testing.F) {
	f.Add(records(RecordHandshake,
		handshakeMsg(HandshakeClientHello, buildClientHello(pqcSpec())), 0))
	f.Add(records(RecordHandshake,
		handshakeMsg(HandshakeClientHello, buildClientHello(pqcSpec())), 64))
	f.Add(records(RecordHandshake,
		handshakeMsg(HandshakeServerHello, buildServerHello(shSpec{
			Cipher: 0x1301, SelectedVersion: 0x0304, Group: 0x11ec,
		})), 0))
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if ch, err := FindClientHello(data); err == nil && ch != nil {
			// Accessors must be safe on anything the parser will return.
			_ = ch.NegotiatedVersion()
			_ = ch.JA4()
			for _, g := range ch.KeyShareGroups {
				_ = Group(g)
			}
			for _, c := range ch.CipherSuites {
				_ = Cipher(c)
			}
		}
		if sh, err := FindServerHello(data); err == nil && sh != nil {
			_ = sh.NegotiatedVersion()
			_ = sh.JA4S(false)
			_ = Group(sh.Group)
			_ = Cipher(sh.CipherSuite)
		}
	})
}
