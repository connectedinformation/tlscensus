package tlsparse

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// Extension type codepoints.
const (
	ExtServerName              uint16 = 0
	ExtMaxFragmentLength       uint16 = 1
	ExtStatusRequest           uint16 = 5
	ExtSupportedGroups         uint16 = 10
	ExtECPointFormats          uint16 = 11
	ExtSignatureAlgorithms     uint16 = 13
	ExtUseSRTP                 uint16 = 14
	ExtHeartbeat               uint16 = 15
	ExtALPN                    uint16 = 16
	ExtSignedCertTimestamp     uint16 = 18
	ExtClientCertType          uint16 = 19
	ExtServerCertType          uint16 = 20
	ExtPadding                 uint16 = 21
	ExtEncryptThenMAC          uint16 = 22
	ExtExtendedMasterSecret    uint16 = 23
	ExtCompressCertificate     uint16 = 27
	ExtRecordSizeLimit         uint16 = 28
	ExtDelegatedCredential     uint16 = 34
	ExtSessionTicket           uint16 = 35
	ExtPreSharedKey            uint16 = 41
	ExtEarlyData               uint16 = 42
	ExtSupportedVersions       uint16 = 43
	ExtCookie                  uint16 = 44
	ExtPSKKeyExchangeModes     uint16 = 45
	ExtCertificateAuthorities  uint16 = 47
	ExtPostHandshakeAuth       uint16 = 49
	ExtSignatureAlgorithmsCert uint16 = 50
	ExtKeyShare                uint16 = 51
	ExtQUICTransportParams     uint16 = 57
	ExtNextProtocolNegotiation uint16 = 13172
	ExtApplicationSettings     uint16 = 17513
	ExtApplicationSettingsOld  uint16 = 17613
	ExtEncryptedClientHello    uint16 = 0xfe0d
	ExtRenegotiationInfo       uint16 = 0xff01
)

var extensionNames = map[uint16]string{
	ExtServerName:              "server_name",
	ExtMaxFragmentLength:       "max_fragment_length",
	ExtStatusRequest:           "status_request",
	ExtSupportedGroups:         "supported_groups",
	ExtECPointFormats:          "ec_point_formats",
	ExtSignatureAlgorithms:     "signature_algorithms",
	ExtUseSRTP:                 "use_srtp",
	ExtHeartbeat:               "heartbeat",
	ExtALPN:                    "application_layer_protocol_negotiation",
	ExtSignedCertTimestamp:     "signed_certificate_timestamp",
	ExtClientCertType:          "client_certificate_type",
	ExtServerCertType:          "server_certificate_type",
	ExtPadding:                 "padding",
	ExtEncryptThenMAC:          "encrypt_then_mac",
	ExtExtendedMasterSecret:    "extended_master_secret",
	ExtCompressCertificate:     "compress_certificate",
	ExtRecordSizeLimit:         "record_size_limit",
	ExtDelegatedCredential:     "delegated_credential",
	ExtSessionTicket:           "session_ticket",
	ExtPreSharedKey:            "pre_shared_key",
	ExtEarlyData:               "early_data",
	ExtSupportedVersions:       "supported_versions",
	ExtCookie:                  "cookie",
	ExtPSKKeyExchangeModes:     "psk_key_exchange_modes",
	ExtCertificateAuthorities:  "certificate_authorities",
	ExtPostHandshakeAuth:       "post_handshake_auth",
	ExtSignatureAlgorithmsCert: "signature_algorithms_cert",
	ExtKeyShare:                "key_share",
	ExtQUICTransportParams:     "quic_transport_parameters",
	ExtNextProtocolNegotiation: "next_protocol_negotiation",
	ExtApplicationSettings:     "application_settings",
	ExtApplicationSettingsOld:  "application_settings_old",
	ExtEncryptedClientHello:    "encrypted_client_hello",
	ExtRenegotiationInfo:       "renegotiation_info",
}

// ExtensionName returns the registered name for an extension codepoint, or
// its hex form when unrecognised.
func ExtensionName(id uint16) string {
	if n, ok := extensionNames[id]; ok {
		return n
	}
	if IsGREASE(id) {
		return fmt.Sprintf("GREASE(%#04x)", id)
	}
	return fmt.Sprintf("%#04x", id)
}

// ECHInfo records what an encrypted_client_hello extension reveals.
//
// This matters more than it looks. When ECH is in use the SNI visible on
// the wire is the public "outer" name of the provider, not the host the
// client actually asked for. An inventory that records it as the
// destination is not degraded, it is wrong, so every observation carries
// this flag and consumers are expected to report ECH flows separately
// rather than folding them into hostname counts.
type ECHInfo struct {
	// Outer is true for ClientHelloOuter (the handshake visible on the
	// wire), false for ClientHelloInner (only seen after decryption, so
	// effectively never in passive capture).
	Outer    bool   `json:"outer"`
	KDFID    uint16 `json:"kdf_id,omitempty"`
	AEADID   uint16 `json:"aead_id,omitempty"`
	ConfigID uint8  `json:"config_id,omitempty"`
}

// readUint16List reads a uint16-length-prefixed vector of uint16 values.
func readUint16List(s *cryptobyte.String, out *[]uint16) bool {
	var v cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&v) {
		return false
	}
	return collectUint16(v, out)
}

// readUint8PrefixedUint16List reads a uint8-length-prefixed vector of uint16
// values. Used by supported_versions in a ClientHello.
func readUint8PrefixedUint16List(s *cryptobyte.String, out *[]uint16) bool {
	var v cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&v) {
		return false
	}
	return collectUint16(v, out)
}

func collectUint16(v cryptobyte.String, out *[]uint16) bool {
	if len(v)%2 != 0 {
		return false
	}
	list := make([]uint16, 0, len(v)/2)
	for !v.Empty() {
		var x uint16
		if !v.ReadUint16(&x) {
			return false
		}
		list = append(list, x)
	}
	*out = list
	return true
}

// parseServerName extracts the host_name entry from a server_name extension.
// Only name_type 0 is defined and only one entry is permitted in practice.
func parseServerName(body cryptobyte.String) (string, bool) {
	var list cryptobyte.String
	if !body.ReadUint16LengthPrefixed(&list) {
		return "", false
	}
	for !list.Empty() {
		var nameType uint8
		var name cryptobyte.String
		if !list.ReadUint8(&nameType) || !list.ReadUint16LengthPrefixed(&name) {
			return "", false
		}
		if nameType == 0 {
			return string(name), true
		}
	}
	return "", true
}

// parseALPN extracts the protocol name list from an ALPN extension.
func parseALPN(body cryptobyte.String) ([]string, bool) {
	var list cryptobyte.String
	if !body.ReadUint16LengthPrefixed(&list) {
		return nil, false
	}
	var out []string
	for !list.Empty() {
		var name cryptobyte.String
		if !list.ReadUint8LengthPrefixed(&name) {
			return nil, false
		}
		out = append(out, string(name))
	}
	return out, true
}

// parseECH decodes an encrypted_client_hello extension body.
func parseECH(body cryptobyte.String) (*ECHInfo, bool) {
	var kind uint8
	if !body.ReadUint8(&kind) {
		return nil, false
	}
	switch kind {
	case 0: // ClientHelloOuter
		info := &ECHInfo{Outer: true}
		var enc, payload cryptobyte.String
		if !body.ReadUint16(&info.KDFID) ||
			!body.ReadUint16(&info.AEADID) ||
			!body.ReadUint8(&info.ConfigID) ||
			!body.ReadUint16LengthPrefixed(&enc) ||
			!body.ReadUint16LengthPrefixed(&payload) {
			return nil, false
		}
		return info, true
	case 1: // ClientHelloInner, empty body
		return &ECHInfo{Outer: false}, true
	}
	return nil, false
}
