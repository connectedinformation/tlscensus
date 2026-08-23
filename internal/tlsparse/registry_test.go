package tlsparse

import "testing"

func TestCipherProperties(t *testing.T) {
	tests := []struct {
		id   uint16
		want CipherProperties
	}{
		{0x1301, CipherProperties{
			Name: "TLS_AES_128_GCM_SHA256", Encryption: "AES_128_GCM", MAC: "AEAD",
			ForwardSecrecy: true, AEAD: true, TLS13: true, Known: true,
		}},
		{0x1303, CipherProperties{
			Name: "TLS_CHACHA20_POLY1305_SHA256", Encryption: "CHACHA20_POLY1305",
			MAC: "AEAD", ForwardSecrecy: true, AEAD: true, TLS13: true, Known: true,
		}},
		{0xc02f, CipherProperties{
			Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", KeyExchange: "ECDHE",
			Authentication: "RSA", Encryption: "AES_128_GCM", MAC: "AEAD",
			ForwardSecrecy: true, AEAD: true, Known: true,
		}},
		{0xc013, CipherProperties{
			Name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", KeyExchange: "ECDHE",
			Authentication: "RSA", Encryption: "AES_128_CBC", MAC: "SHA",
			ForwardSecrecy: true, Known: true,
		}},
		// Static RSA: no forward secrecy, which is the point of flagging it.
		{0x009c, CipherProperties{
			Name: "TLS_RSA_WITH_AES_128_GCM_SHA256", KeyExchange: "RSA",
			Authentication: "RSA", Encryption: "AES_128_GCM", MAC: "AEAD",
			AEAD: true, Known: true,
		}},
		{0x000a, CipherProperties{
			Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", KeyExchange: "RSA",
			Authentication: "RSA", Encryption: "3DES_EDE_CBC", MAC: "SHA", Known: true,
		}},
		{0x0004, CipherProperties{
			Name: "TLS_RSA_WITH_RC4_128_MD5", KeyExchange: "RSA",
			Authentication: "RSA", Encryption: "RC4_128", MAC: "MD5", Known: true,
		}},
		{0x0008, CipherProperties{
			Name: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", KeyExchange: "RSA",
			Authentication: "RSA", Encryption: "DES40_CBC", MAC: "SHA",
			Export: true, Known: true,
		}},
		// Anonymous key exchange is ephemeral but unauthenticated, so it
		// must not be credited with forward secrecy.
		{0x0034, CipherProperties{
			Name: "TLS_DH_anon_WITH_AES_128_CBC_SHA", KeyExchange: "DH_anon",
			Authentication: "anon", Encryption: "AES_128_CBC", MAC: "SHA",
			Anonymous: true, Known: true,
		}},
		{0x0002, CipherProperties{
			Name: "TLS_RSA_WITH_NULL_SHA", KeyExchange: "RSA",
			Authentication: "RSA", Encryption: "NULL", MAC: "SHA", Known: true,
		}},
		{0x00ff, CipherProperties{
			Name: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", Signalling: true, Known: true,
		}},
	}
	for _, tt := range tests {
		if got := Cipher(tt.id); got != tt.want {
			t.Errorf("Cipher(%#04x):\n got %+v\nwant %+v", tt.id, got, tt.want)
		}
	}
}

func TestCipherUnknown(t *testing.T) {
	got := Cipher(0xabcd)
	if got.Known {
		t.Error("Known = true for an unassigned codepoint")
	}
	if got.Name != "0xabcd" {
		t.Errorf("Name = %q, want 0xabcd", got.Name)
	}
}

func TestGroupProperties(t *testing.T) {
	tests := []struct {
		id                         uint16
		name                       string
		postQuantum, hybrid, known bool
	}{
		{29, "x25519", false, false, true},
		{23, "secp256r1", false, false, true},
		{256, "ffdhe2048", false, false, true},
		{0x11ec, "X25519MLKEM768", true, true, true},
		{0x11eb, "SecP256r1MLKEM768", true, true, true},
		{0x6399, "X25519Kyber768Draft00", true, true, true},
		// Pure ML-KEM drops the classical component entirely.
		{0x0201, "MLKEM768", true, false, true},
		{0x9999, "0x9999", false, false, false},
	}
	for _, tt := range tests {
		g := Group(tt.id)
		if g.Name != tt.name || g.PostQuantum != tt.postQuantum ||
			g.Hybrid != tt.hybrid || g.Known != tt.known {
			t.Errorf("Group(%#04x) = %+v, want name=%s pq=%v hybrid=%v known=%v",
				tt.id, g, tt.name, tt.postQuantum, tt.hybrid, tt.known)
		}
	}
}

func TestVersionName(t *testing.T) {
	for v, want := range map[uint16]string{
		0x0304: "TLS 1.3", 0x0303: "TLS 1.2", 0x0302: "TLS 1.1",
		0x0301: "TLS 1.0", 0x0300: "SSL 3.0", 0x0a0a: "GREASE(0x0a0a)",
	} {
		if got := VersionName(v); got != want {
			t.Errorf("VersionName(%#04x) = %q, want %q", v, got, want)
		}
	}
}

func TestSigAlgPostQuantum(t *testing.T) {
	if !SigAlgPostQuantum(0x0905) {
		t.Error("mldsa65 not reported as post-quantum")
	}
	if SigAlgPostQuantum(0x0804) {
		t.Error("rsa_pss_rsae_sha256 reported as post-quantum")
	}
}
