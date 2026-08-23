package tlsparse

import "golang.org/x/crypto/cryptobyte"

// ClientHello is the decoded content of a TLS ClientHello.
//
// All codepoint lists are GREASE-free (RFC 8701) and preserve wire order,
// which JA4 depends on. Whether GREASE was present at all is recorded in
// the GREASE field.
type ClientHello struct {
	LegacyVersion      uint16   `json:"legacy_version"`
	SessionIDLen       int      `json:"session_id_len"`
	CipherSuites       []uint16 `json:"cipher_suites"`
	CompressionMethods []uint8  `json:"compression_methods"`
	// Extensions lists extension codepoints in the order they appeared.
	Extensions []uint16 `json:"extensions"`

	ServerName        string   `json:"server_name,omitempty"`
	ALPN              []string `json:"alpn,omitempty"`
	SupportedVersions []uint16 `json:"supported_versions,omitempty"`
	SupportedGroups   []uint16 `json:"supported_groups,omitempty"`

	// KeyShareGroups are the groups the client actually sent a key share
	// for, in offer order.
	//
	// This is not the same signal as SupportedGroups and the difference is
	// the whole point of a PQ-readiness inventory. SupportedGroups says what
	// the client would accept; KeyShareGroups says what it spent bytes
	// betting on. A client that advertises X25519MLKEM768 in supported
	// groups but only key-shares x25519 will complete a classical handshake
	// against any server that takes the offer, and is not post-quantum in
	// practice.
	KeyShareGroups []uint16 `json:"key_share_groups,omitempty"`

	SignatureAlgorithms     []uint16 `json:"signature_algorithms,omitempty"`
	SignatureAlgorithmsCert []uint16 `json:"signature_algorithms_cert,omitempty"`
	PSKKeyExchangeModes     []uint8  `json:"psk_key_exchange_modes,omitempty"`

	HasPreSharedKey         bool `json:"has_pre_shared_key,omitempty"`
	HasEarlyData            bool `json:"has_early_data,omitempty"`
	HasSessionTicket        bool `json:"has_session_ticket,omitempty"`
	HasExtendedMasterSecret bool `json:"has_extended_master_secret,omitempty"`
	HasRenegotiationInfo    bool `json:"has_renegotiation_info,omitempty"`
	HasStatusRequest        bool `json:"has_status_request,omitempty"`
	// QUIC is true when quic_transport_parameters is present, which marks
	// this as a QUIC handshake rather than TLS over TCP. It feeds the
	// protocol character of JA4.
	QUIC bool `json:"quic,omitempty"`

	// ECH is set when an encrypted_client_hello extension was present. When
	// it is, ServerName is the public outer name, not the real destination.
	ECH *ECHInfo `json:"ech,omitempty"`

	// GREASE reports whether any GREASE codepoint was observed. Its absence
	// is itself informative: most modern browsers always send it.
	GREASE bool `json:"grease"`

	// Truncated is true when the extension block ran past the available
	// bytes. Fields decoded before that point are still valid.
	Truncated bool `json:"truncated,omitempty"`
}

// NegotiatedVersion returns the highest protocol version the client offered:
// the maximum of supported_versions when present, otherwise the legacy
// version field. GREASE values are already excluded.
func (ch *ClientHello) NegotiatedVersion() uint16 {
	max := uint16(0)
	for _, v := range ch.SupportedVersions {
		if v > max {
			max = v
		}
	}
	if max != 0 {
		return max
	}
	return ch.LegacyVersion
}

// ParseClientHello decodes a ClientHello handshake message body, excluding
// the four-byte handshake header.
func ParseClientHello(body []byte) (*ClientHello, error) {
	s := cryptobyte.String(body)
	ch := &ClientHello{}

	var sessionID, compression cryptobyte.String
	if !s.ReadUint16(&ch.LegacyVersion) {
		return nil, ErrTruncated
	}
	if !s.Skip(32) { // client_random
		return nil, ErrTruncated
	}
	if !s.ReadUint8LengthPrefixed(&sessionID) {
		return nil, ErrTruncated
	}
	ch.SessionIDLen = len(sessionID)

	var suites []uint16
	if !readUint16List(&s, &suites) {
		return nil, ErrMalformed
	}
	suites, greased := stripGREASE(suites)
	ch.CipherSuites = suites
	ch.GREASE = greased

	if !s.ReadUint8LengthPrefixed(&compression) {
		return nil, ErrTruncated
	}
	ch.CompressionMethods = []byte(compression)

	// Extensions are optional: an SSLv3-era ClientHello simply ends here.
	if s.Empty() {
		return ch, nil
	}
	var exts cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&exts) {
		ch.Truncated = true
		return ch, nil
	}
	ch.parseExtensions(exts)
	return ch, nil
}

func (ch *ClientHello) parseExtensions(exts cryptobyte.String) {
	for !exts.Empty() {
		var extType uint16
		var body cryptobyte.String
		if !exts.ReadUint16(&extType) || !exts.ReadUint16LengthPrefixed(&body) {
			ch.Truncated = true
			return
		}
		if IsGREASE(extType) {
			ch.GREASE = true
			continue
		}
		ch.Extensions = append(ch.Extensions, extType)

		// A malformed individual extension is recorded as present and then
		// skipped. One bad extension should not discard an otherwise
		// readable handshake, and refusing to decode is how a parser turns
		// a hostile packet into a blind spot.
		switch extType {
		case ExtServerName:
			if name, ok := parseServerName(body); ok {
				ch.ServerName = name
			}
		case ExtALPN:
			if list, ok := parseALPN(body); ok {
				ch.ALPN = list
			}
		case ExtSupportedVersions:
			var vs []uint16
			if readUint8PrefixedUint16List(&body, &vs) {
				vs, g := stripGREASE(vs)
				ch.SupportedVersions = vs
				ch.GREASE = ch.GREASE || g
			}
		case ExtSupportedGroups:
			var gs []uint16
			if readUint16List(&body, &gs) {
				gs, g := stripGREASE(gs)
				ch.SupportedGroups = gs
				ch.GREASE = ch.GREASE || g
			}
		case ExtSignatureAlgorithms:
			var sa []uint16
			if readUint16List(&body, &sa) {
				sa, g := stripGREASE(sa)
				ch.SignatureAlgorithms = sa
				ch.GREASE = ch.GREASE || g
			}
		case ExtSignatureAlgorithmsCert:
			var sa []uint16
			if readUint16List(&body, &sa) {
				sa, _ = stripGREASE(sa)
				ch.SignatureAlgorithmsCert = sa
			}
		case ExtKeyShare:
			ch.parseKeyShare(body)
		case ExtPSKKeyExchangeModes:
			var modes cryptobyte.String
			if body.ReadUint8LengthPrefixed(&modes) {
				ch.PSKKeyExchangeModes = []byte(modes)
			}
		case ExtEncryptedClientHello:
			if info, ok := parseECH(body); ok {
				ch.ECH = info
			} else {
				ch.ECH = &ECHInfo{Outer: true}
			}
		case ExtPreSharedKey:
			ch.HasPreSharedKey = true
		case ExtEarlyData:
			ch.HasEarlyData = true
		case ExtSessionTicket:
			ch.HasSessionTicket = true
		case ExtExtendedMasterSecret:
			ch.HasExtendedMasterSecret = true
		case ExtRenegotiationInfo:
			ch.HasRenegotiationInfo = true
		case ExtStatusRequest:
			ch.HasStatusRequest = true
		case ExtQUICTransportParams:
			ch.QUIC = true
		}
	}
}

// parseKeyShare reads the client_shares vector, keeping only the group of
// each entry. The key exchange payloads themselves are of no inventory
// interest and are the bulk of the bytes: a single X25519MLKEM768 share is
// over a kilobyte, which is why post-quantum ClientHellos routinely exceed
// one TCP segment.
func (ch *ClientHello) parseKeyShare(body cryptobyte.String) {
	var shares cryptobyte.String
	if !body.ReadUint16LengthPrefixed(&shares) {
		return
	}
	var groups []uint16
	for !shares.Empty() {
		var group uint16
		var key cryptobyte.String
		if !shares.ReadUint16(&group) || !shares.ReadUint16LengthPrefixed(&key) {
			return
		}
		if IsGREASE(group) {
			ch.GREASE = true
			continue
		}
		groups = append(groups, group)
	}
	ch.KeyShareGroups = groups
}
