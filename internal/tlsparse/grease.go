package tlsparse

// IsGREASE reports whether v is a GREASE value as defined by RFC 8701.
//
// The sixteen reserved values are 0x0a0a, 0x1a1a, ... 0xfafa: both bytes
// are equal and both low nibbles are 0xa. Clients (notably BoringSSL)
// inject them into cipher suite, extension, named group, ALPN and
// signature algorithm lists to keep servers tolerant of unknown values.
//
// An inventory that does not strip them reports phantom "unknown cipher
// 0x8a8a" rows for a large share of real-world traffic, so every list
// this package exposes is GREASE-free by construction. Whether GREASE was
// observed at all is recorded separately on the ClientHello, since its
// presence is itself a fingerprinting signal.
func IsGREASE(v uint16) bool {
	return byte(v>>8) == byte(v) && v&0x0f == 0x0a
}

// stripGREASE returns in with GREASE values removed, reporting whether any
// were present. It allocates only when a GREASE value is actually found.
func stripGREASE(in []uint16) (out []uint16, found bool) {
	for i, v := range in {
		if !IsGREASE(v) {
			continue
		}
		out = make([]uint16, 0, len(in)-1)
		out = append(out, in[:i]...)
		for _, v := range in[i+1:] {
			if !IsGREASE(v) {
				out = append(out, v)
			}
		}
		return out, true
	}
	return in, false
}
