package tlsparse

import "github.com/connectedinformation/tlscensus/internal/tlssynth"

// Thin adapters over tlssynth, which owns the synthetic-handshake builders.
// It defines its own codepoint constants rather than importing this package,
// so these tests check the parser against an independent encoding of the
// RFCs rather than against itself.

type chSpec = tlssynth.ClientHelloSpec
type shSpec = tlssynth.ServerHelloSpec

func buildClientHello(s chSpec) []byte { return tlssynth.ClientHello(s) }
func buildServerHello(s shSpec) []byte { return tlssynth.ServerHello(s) }

func handshakeMsg(typ uint8, body []byte) []byte { return tlssynth.HandshakeMsg(typ, body) }
func records(contentType uint8, payload []byte, chunk int) []byte {
	return tlssynth.Records(contentType, payload, chunk)
}

// helloRetryRequestRandom is asserted here to be the same value the parser
// matches on, so a drift between the two shows up as a test failure rather
// than as silently unrecognised HelloRetryRequests.
var _ = func() bool {
	if string(helloRetryRequestRandom) != string(tlssynth.HelloRetryRequestRandom) {
		panic("tlsparse and tlssynth disagree on the HelloRetryRequest random")
	}
	return true
}()
