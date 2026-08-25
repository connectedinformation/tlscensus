package inventory

import (
	"fmt"
	"strings"
	"time"

	"github.com/connectedinformation/tlscensus/internal/assemble"
	"github.com/connectedinformation/tlscensus/internal/tlsparse"
)

// Finding identifiers. Stable strings: reports, filters and any downstream
// tooling key off these, so they are part of the output contract.
const (
	FindingObsoleteProtocol   = "obsolete_protocol"
	FindingLegacyProtocol     = "legacy_protocol"
	FindingBrokenCipher       = "broken_cipher"
	FindingWeakCipher         = "weak_cipher"
	FindingNoForwardSecrecy   = "no_forward_secrecy"
	FindingAnonymousKeyExch   = "anonymous_key_exchange"
	FindingExportCipher       = "export_cipher"
	FindingNullEncryption     = "null_encryption"
	FindingSHA1Signature      = "sha1_signature"
	FindingCompressionOffered = "compression_offered"
	FindingClassicalKeyExch   = "classical_key_exchange"
	FindingECHInUse           = "ech_in_use"
	FindingWeakCertKey        = "weak_certificate_key"
	FindingCertExpired        = "certificate_expired"
	FindingCertSHA1           = "certificate_sha1_signature"
	FindingUnknownCipher      = "unknown_cipher"
)

// now is a variable so tests can pin certificate expiry checks.
var now = time.Now

func findings(f *assemble.Flow, r *Record, cipher tlsparse.CipherProperties) []Finding {
	var out []Finding
	add := func(id string, sev Severity, format string, args ...any) {
		out = append(out, Finding{ID: id, Severity: sev, Detail: fmt.Sprintf(format, args...)})
	}

	// --- protocol version -------------------------------------------------
	// Judge the negotiated version when it was observed, otherwise the best
	// the client was willing to do. A client offering only TLS 1.0 is worth
	// flagging even when the response was not captured.
	version := f.Client.NegotiatedVersion()
	if f.Server != nil {
		version = f.Server.NegotiatedVersion()
	}
	switch {
	case version < 0x0303:
		add(FindingObsoleteProtocol, SevCritical,
			"%s is deprecated and prohibited by RFC 8996", tlsparse.VersionName(version))
	case version == 0x0303:
		add(FindingLegacyProtocol, SevLow,
			"TLS 1.2 in use; TLS 1.3 removes the negotiable-weakness surface entirely")
	}

	// --- cipher suite -----------------------------------------------------
	if f.Server != nil {
		switch {
		case !cipher.Known:
			add(FindingUnknownCipher, SevInfo,
				"negotiated cipher suite %s is not in this build's registry", cipher.Name)
		case cipher.Anonymous:
			add(FindingAnonymousKeyExch, SevCritical,
				"%s performs no server authentication", cipher.Name)
		case cipher.Export:
			add(FindingExportCipher, SevCritical,
				"%s is export-grade (FREAK/Logjam class)", cipher.Name)
		}
		if strings.Contains(cipher.Encryption, "NULL") {
			add(FindingNullEncryption, SevCritical,
				"%s provides no confidentiality", cipher.Name)
		}
		switch {
		case strings.HasPrefix(cipher.Encryption, "RC4"),
			strings.Contains(cipher.Encryption, "DES40"),
			cipher.Encryption == "DES_CBC",
			cipher.Encryption == "RC2_CBC_40":
			add(FindingBrokenCipher, SevCritical,
				"%s uses broken primitive %s", cipher.Name, cipher.Encryption)
		case strings.HasPrefix(cipher.Encryption, "3DES"):
			add(FindingWeakCipher, SevHigh,
				"%s uses 3DES (64-bit block, Sweet32)", cipher.Name)
		}
		if cipher.MAC == "MD5" {
			add(FindingWeakCipher, SevHigh, "%s authenticates with MD5", cipher.Name)
		} else if cipher.MAC == "SHA" {
			add(FindingSHA1Signature, SevMedium,
				"%s authenticates with SHA-1 in a MAC-then-encrypt construction", cipher.Name)
		}
		if cipher.Known && !cipher.ForwardSecrecy && !cipher.Anonymous && !cipher.Signalling {
			add(FindingNoForwardSecrecy, SevHigh,
				"%s has no forward secrecy; recorded traffic is decryptable if the server key leaks",
				cipher.Name)
		}
	}

	// --- client-offered weaknesses ---------------------------------------
	for _, m := range f.Client.CompressionMethods {
		if m != 0 {
			add(FindingCompressionOffered, SevMedium,
				"client offered TLS compression method %d (CRIME)", m)
			break
		}
	}

	// --- post-quantum readiness ------------------------------------------
	// Not a vulnerability today. It is reported at info so a migration
	// programme can count it without it polluting a security severity roll-up.
	switch r.PQ {
	case PQClassical:
		add(FindingClassicalKeyExch, SevInfo,
			"key exchange is classical only; not resistant to harvest-now-decrypt-later")
	case PQAdvertised:
		add(FindingClassicalKeyExch, SevInfo,
			"post-quantum groups advertised but no key share sent; no PQ handshake will occur")
	case PQOffered:
		add(FindingClassicalKeyExch, SevInfo,
			"client offered a post-quantum key share; the server did not select it")
	}

	// --- ECH --------------------------------------------------------------
	if f.Client.ECH != nil {
		add(FindingECHInUse, SevInfo,
			"encrypted_client_hello present; server_name %q is the public outer name, not the destination",
			f.Client.ServerName)
	}

	// --- certificates (TLS 1.2 and below only) ---------------------------
	for i, c := range r.Certificates {
		leaf := i == 0
		if c.PublicKeyAlgorithm == "RSA" && c.KeyBits > 0 && c.KeyBits < 2048 {
			add(FindingWeakCertKey, SevHigh,
				"certificate %q has a %d-bit RSA key", c.Subject, c.KeyBits)
		}
		if leaf && c.NotAfter.Before(now()) {
			add(FindingCertExpired, SevMedium,
				"certificate %q expired %s", c.Subject, c.NotAfter.Format(time.DateOnly))
		}
		if strings.Contains(strings.ToUpper(c.SignatureAlgorithm), "SHA1") && !c.SelfSigned {
			add(FindingCertSHA1, SevHigh,
				"certificate %q is signed with SHA-1", c.Subject)
		}
	}

	return out
}
