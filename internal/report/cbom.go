package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/tlscensus/tlscensus/internal/inventory"
	"github.com/tlscensus/tlscensus/internal/tlsparse"
)

// CycloneDX 1.6 cryptographic bill of materials.
//
// A CBOM is the reason to emit a machine-readable format at all: it makes
// this tool a feed into procurement and compliance tooling rather than one
// more dashboard to log into. The 1.6 spec added `cryptographic-asset`
// components precisely for post-quantum migration tracking, which is the
// same question the inventory answers.
//
// Only what was observed on the wire is emitted. Nothing is inferred from a
// hostname or a library name, and an asset appears only because a handshake
// negotiated it.

const cycloneDXSpecVersion = "1.6"

type cdxBOM struct {
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	SerialNumber string          `json:"serialNumber"`
	Version      int             `json:"version"`
	Metadata     cdxMetadata     `json:"metadata"`
	Components   []cdxComponent  `json:"components"`
	Dependencies []cdxDependency `json:"dependencies,omitempty"`
}

type cdxMetadata struct {
	Timestamp string   `json:"timestamp"`
	Tools     cdxTools `json:"tools"`
}

type cdxTools struct {
	Components []cdxToolComponent `json:"components"`
}

type cdxToolComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cdxComponent struct {
	Type             string          `json:"type"`
	BOMRef           string          `json:"bom-ref"`
	Name             string          `json:"name"`
	CryptoProperties *cdxCryptoProps `json:"cryptoProperties,omitempty"`
	Properties       []cdxProperty   `json:"properties,omitempty"`
	Evidence         *cdxEvidence    `json:"evidence,omitempty"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxEvidence struct {
	Occurrences []cdxOccurrence `json:"occurrences,omitempty"`
}

type cdxOccurrence struct {
	BOMRef   string `json:"bom-ref,omitempty"`
	Location string `json:"location"`
}

type cdxCryptoProps struct {
	AssetType           string               `json:"assetType"`
	AlgorithmProperties *cdxAlgorithmProps   `json:"algorithmProperties,omitempty"`
	ProtocolProperties  *cdxProtocolProps    `json:"protocolProperties,omitempty"`
	CertificateProps    *cdxCertificateProps `json:"certificateProperties,omitempty"`
}

type cdxAlgorithmProps struct {
	Primitive                string   `json:"primitive,omitempty"`
	ParameterSetIdentifier   string   `json:"parameterSetIdentifier,omitempty"`
	ExecutionEnvironment     string   `json:"executionEnvironment,omitempty"`
	ImplementationPlatform   string   `json:"implementationPlatform,omitempty"`
	CryptoFunctions          []string `json:"cryptoFunctions,omitempty"`
	ClassicalSecurityLevel   *int     `json:"classicalSecurityLevel,omitempty"`
	NISTQuantumSecurityLevel *int     `json:"nistQuantumSecurityLevel,omitempty"`
}

type cdxProtocolProps struct {
	Type         string           `json:"type,omitempty"`
	Version      string           `json:"version,omitempty"`
	CipherSuites []cdxCipherSuite `json:"cipherSuites,omitempty"`
	CryptoRefs   []string         `json:"cryptoRefArray,omitempty"`
}

type cdxCipherSuite struct {
	Name        string   `json:"name"`
	Algorithms  []string `json:"algorithms,omitempty"`
	Identifiers []string `json:"identifiers,omitempty"`
}

type cdxCertificateProps struct {
	SubjectName           string `json:"subjectName,omitempty"`
	IssuerName            string `json:"issuerName,omitempty"`
	NotValidAfter         string `json:"notValidAfter,omitempty"`
	CertificateFormat     string `json:"certificateFormat,omitempty"`
	SignatureAlgorithmRef string `json:"signatureAlgorithmRef,omitempty"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// WriteCBOM renders the inventory as a CycloneDX 1.6 CBOM.
func WriteCBOM(w io.Writer, r *Report, records []*inventory.Record) error {
	b := buildCBOM(r, records)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(b)
}

// asset accumulates one crypto asset and where it was seen.
type asset struct {
	comp  cdxComponent
	seen  map[string]bool
	count int
}

type cbomBuilder struct {
	assets map[string]*asset
	order  []string
}

func (b *cbomBuilder) add(ref string, make func() cdxComponent, where string) string {
	a, ok := b.assets[ref]
	if !ok {
		a = &asset{comp: make(), seen: map[string]bool{}}
		b.assets[ref] = a
		b.order = append(b.order, ref)
	}
	a.count++
	if where != "" {
		a.seen[where] = true
	}
	return ref
}

// addCipherSuite records a suite under an already-created protocol asset.
func (b *cbomBuilder) addCipherSuite(protoRef, cipher string) {
	a, ok := b.assets[protoRef]
	if !ok || a.comp.CryptoProperties == nil || a.comp.CryptoProperties.ProtocolProperties == nil {
		return
	}
	pp := a.comp.CryptoProperties.ProtocolProperties
	for _, cs := range pp.CipherSuites {
		if cs.Name == cipher {
			return
		}
	}
	pp.CipherSuites = append(pp.CipherSuites, cdxCipherSuite{
		Name:        cipher,
		Identifiers: []string{cipherIdentifier(cipher)},
	})
}

func buildCBOM(r *Report, records []*inventory.Record) *cdxBOM {
	b := &cbomBuilder{assets: map[string]*asset{}}
	deps := map[string]map[string]bool{}

	for _, rec := range records {
		// Only negotiated cryptography is an asset. What a client merely
		// offered is a capability, not something in use, and conflating the
		// two is how an inventory overstates its own findings.
		if !rec.ServerObserved || rec.CipherSuite == "" {
			continue
		}
		where := rec.ServerName
		if where == "" {
			where = fmt.Sprintf("%s:%d", rec.ServerIP, rec.ServerPort)
		}
		if rec.ECH {
			// The visible name is the provider's, not the destination's.
			where = fmt.Sprintf("%s:%d", rec.ServerIP, rec.ServerPort)
		}

		protoRef := "crypto/protocol/tls/" + slug(rec.Version)
		cipherRef := "crypto/algorithm/" + slug(rec.CipherSuite)
		b.add(cipherRef, func() cdxComponent {
			return cipherComponent(rec.CipherSuite)
		}, where)

		refs := []string{cipherRef}
		if rec.Group != "" {
			groupRef := "crypto/algorithm/" + slug(rec.Group)
			b.add(groupRef, func() cdxComponent { return groupComponent(rec.Group) }, where)
			refs = append(refs, groupRef)
		}

		version := rec.Version
		cipher := rec.CipherSuite
		b.add(protoRef, func() cdxComponent {
			return cdxComponent{
				Type:   "cryptographic-asset",
				BOMRef: protoRef,
				Name:   version,
				CryptoProperties: &cdxCryptoProps{
					AssetType: "protocol",
					ProtocolProperties: &cdxProtocolProps{
						Type:    "tls",
						Version: protocolVersionNumber(version),
					},
				},
			}
		}, where)

		// A protocol version is negotiated with many suites; the component
		// must list all of them, not whichever was seen first.
		b.addCipherSuite(protoRef, cipher)

		if deps[protoRef] == nil {
			deps[protoRef] = map[string]bool{}
		}
		for _, ref := range refs {
			deps[protoRef][ref] = true
		}

		for _, c := range rec.Certificates {
			certRef := "crypto/certificate/" + slug(c.Subject+"/"+c.SignatureAlgorithm)
			cert := c
			b.add(certRef, func() cdxComponent { return certComponent(certRef, cert) }, where)
			if deps[protoRef] == nil {
				deps[protoRef] = map[string]bool{}
			}
			deps[protoRef][certRef] = true
		}
	}

	sort.Strings(b.order)
	components := make([]cdxComponent, 0, len(b.order))
	for _, ref := range b.order {
		a := b.assets[ref]
		c := a.comp
		c.Properties = append(c.Properties, cdxProperty{
			Name:  "tlscensus:observations",
			Value: fmt.Sprint(a.count),
		})
		locs := make([]string, 0, len(a.seen))
		for l := range a.seen {
			locs = append(locs, l)
		}
		sort.Strings(locs)
		if len(locs) > 0 {
			occ := make([]cdxOccurrence, 0, len(locs))
			for _, l := range locs {
				occ = append(occ, cdxOccurrence{Location: l})
			}
			c.Evidence = &cdxEvidence{Occurrences: occ}
		}
		components = append(components, c)
	}

	depRefs := make([]string, 0, len(deps))
	for ref := range deps {
		depRefs = append(depRefs, ref)
	}
	sort.Strings(depRefs)
	dependencies := make([]cdxDependency, 0, len(depRefs))
	for _, ref := range depRefs {
		on := make([]string, 0, len(deps[ref]))
		for d := range deps[ref] {
			on = append(on, d)
		}
		sort.Strings(on)
		dependencies = append(dependencies, cdxDependency{Ref: ref, DependsOn: on})
	}

	ts := r.GeneratedAt
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	bom := &cdxBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: cycloneDXSpecVersion,
		Version:     1,
		Metadata: cdxMetadata{
			Timestamp: ts.UTC().Format(time.RFC3339),
			Tools: cdxTools{Components: []cdxToolComponent{{
				Type: "application", Name: r.Tool, Version: r.Version,
			}}},
		},
		Components:   components,
		Dependencies: dependencies,
	}
	// A serial number derived from the content, not from randomness, so the
	// same inventory produces the same document and two runs can be diffed.
	bom.SerialNumber = deterministicURN(components)
	return bom
}

func cipherComponent(name string) cdxComponent {
	p := lookupCipher(name)
	primitive := cipherPrimitive(p)
	zero := 0
	return cdxComponent{
		Type:   "cryptographic-asset",
		BOMRef: "crypto/algorithm/" + slug(name),
		Name:   name,
		CryptoProperties: &cdxCryptoProps{
			AssetType: "algorithm",
			AlgorithmProperties: &cdxAlgorithmProps{
				Primitive:                primitive,
				CryptoFunctions:          []string{"encrypt", "decrypt"},
				NISTQuantumSecurityLevel: &zero,
			},
		},
	}
}

func groupComponent(name string) cdxComponent {
	g := lookupGroup(name)
	primitive := "key-agree"
	switch {
	case g.PostQuantum && g.Hybrid:
		// A hybrid combines a classical key agreement with a KEM.
		primitive = "combiner"
	case g.PostQuantum:
		primitive = "kem"
	}
	level := nistLevel(name)
	return cdxComponent{
		Type:   "cryptographic-asset",
		BOMRef: "crypto/algorithm/" + slug(name),
		Name:   name,
		CryptoProperties: &cdxCryptoProps{
			AssetType: "algorithm",
			AlgorithmProperties: &cdxAlgorithmProps{
				Primitive:                primitive,
				ParameterSetIdentifier:   name,
				CryptoFunctions:          []string{"keygen"},
				NISTQuantumSecurityLevel: &level,
			},
		},
	}
}

func certComponent(ref string, c inventory.CertInfo) cdxComponent {
	return cdxComponent{
		Type:   "cryptographic-asset",
		BOMRef: ref,
		Name:   c.Subject,
		CryptoProperties: &cdxCryptoProps{
			AssetType: "certificate",
			CertificateProps: &cdxCertificateProps{
				SubjectName:       c.Subject,
				IssuerName:        c.Issuer,
				NotValidAfter:     c.NotAfter.UTC().Format(time.RFC3339),
				CertificateFormat: "X.509",
			},
		},
		Properties: []cdxProperty{
			{Name: "tlscensus:publicKeyAlgorithm", Value: c.PublicKeyAlgorithm},
			{Name: "tlscensus:keyBits", Value: fmt.Sprint(c.KeyBits)},
			{Name: "tlscensus:signatureAlgorithm", Value: c.SignatureAlgorithm},
		},
	}
}

// cipherPrimitive classifies the record layer's bulk cipher. The
// distinction between a block and a stream cipher is not cosmetic here: it
// is the difference between "CBC, and therefore padding-oracle history" and
// "RC4, and therefore biased keystream".
func cipherPrimitive(p tlsparse.CipherProperties) string {
	switch {
	case strings.Contains(p.Encryption, "NULL"):
		return "other"
	case p.AEAD:
		return "ae"
	case strings.HasPrefix(p.Encryption, "RC4"):
		return "stream-cipher"
	case p.Encryption == "":
		return "unknown"
	}
	return "block-cipher"
}

// nistLevel maps a named group to the NIST post-quantum security category.
// Classical groups are category 0: they have no post-quantum security.
func nistLevel(name string) int {
	switch {
	case strings.Contains(name, "MLKEM1024"), strings.Contains(name, "Kyber1024"):
		return 5
	case strings.Contains(name, "MLKEM768"), strings.Contains(name, "Kyber768"):
		return 3
	case strings.Contains(name, "MLKEM512"), strings.Contains(name, "Kyber512"):
		return 1
	}
	return 0
}

func protocolVersionNumber(name string) string {
	return strings.TrimPrefix(strings.TrimPrefix(name, "TLS "), "SSL ")
}

// lookupCipher and lookupGroup recover properties from a rendered name. The
// record carries names rather than codepoints, so the CBOM writer reads them
// back through the registry's reverse index rather than keeping a second
// copy of the table.
func lookupCipher(name string) tlsparse.CipherProperties {
	if id, ok := tlsparse.CipherByName(name); ok {
		return tlsparse.Cipher(id)
	}
	return tlsparse.CipherProperties{Name: name}
}

func lookupGroup(name string) tlsparse.GroupProperties {
	if id, ok := tlsparse.GroupByName(name); ok {
		return tlsparse.Group(id)
	}
	return tlsparse.GroupProperties{Name: name}
}

func cipherIdentifier(name string) string {
	if id, ok := tlsparse.CipherByName(name); ok {
		return fmt.Sprintf("0x%04x", id)
	}
	return name
}

func slug(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.' || r == '-' || r == '_' || r == '/':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func deterministicURN(components []cdxComponent) string {
	h := sha256.New()
	for _, c := range components {
		fmt.Fprintf(h, "%s\n", c.BOMRef)
	}
	sum := h.Sum(nil)
	// Format as a v4-shaped UUID: the value is a digest, not randomness, so
	// the same set of assets always yields the same document identity.
	sum[6] = (sum[6] & 0x0f) | 0x40
	sum[8] = (sum[8] & 0x3f) | 0x80
	s := hex.EncodeToString(sum[:16])
	return fmt.Sprintf("urn:uuid:%s-%s-%s-%s-%s", s[0:8], s[8:12], s[12:16], s[16:20], s[20:32])
}
