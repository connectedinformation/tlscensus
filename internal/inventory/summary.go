package inventory

import (
	"sort"
	"time"
)

// Count is one row of a distribution.
type Count struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// FindingCount aggregates one finding ID across the run.
type FindingCount struct {
	ID       string   `json:"id"`
	Severity Severity `json:"severity"`
	Count    int      `json:"count"`
	Example  string   `json:"example,omitempty"`
}

// Summary is the roll-up over every record.
type Summary struct {
	Flows          int       `json:"flows"`
	ServerObserved int       `json:"server_observed"`
	FirstSeen      time.Time `json:"first_seen,omitempty"`
	LastSeen       time.Time `json:"last_seen,omitempty"`

	Versions   []Count `json:"versions"`
	Ciphers    []Count `json:"ciphers"`
	Groups     []Count `json:"groups"`
	ALPN       []Count `json:"alpn"`
	Transports []Count `json:"transports"`
	JA4        []Count `json:"ja4"`
	ServerName []Count `json:"server_names"`

	PQ []Count `json:"pq_status"`
	// PQReadiness is the fraction of handshakes where a post-quantum group
	// was actually negotiated, out of those where the negotiation was
	// observed at all. Flows with no captured server response are excluded
	// rather than counted as failures.
	PQReadiness float64 `json:"pq_readiness"`

	// ECHOffered counts handshakes carrying an encrypted_client_hello
	// extension. Most are GREASE, so this is not a count of hidden
	// destinations — see Record.ECH.
	ECHOffered int `json:"ech_offered"`
	// ECHLikelyGREASE counts destinations where a config_id that varies
	// across connections shows the extension was a decoy.
	ECHLikelyGREASE int `json:"ech_likely_grease"`

	Findings []FindingCount `json:"findings"`

	// DistinctFindings is how many aggregates the flows collapsed to. The
	// ratio to Flows is a measure of how repetitive the traffic is.
	DistinctFindings  int `json:"distinct_findings"`
	AggregatesDropped int `json:"aggregates_dropped,omitempty"`
}

// Accumulator builds a Summary incrementally.
type Accumulator struct {
	s         Summary
	versions  map[string]int
	ciphers   map[string]int
	groups    map[string]int
	alpn      map[string]int
	transport map[string]int
	ja4       map[string]int
	names     map[string]int
	pq        map[PQStatus]int
	findings  map[string]*FindingCount
	pqDecided int
	pqDone    int

	aggs       map[aggKey]*aggEntry
	aggDropped int
}

// NewAccumulator returns an empty Accumulator.
func NewAccumulator() *Accumulator {
	return &Accumulator{
		versions:  map[string]int{},
		ciphers:   map[string]int{},
		groups:    map[string]int{},
		alpn:      map[string]int{},
		transport: map[string]int{},
		ja4:       map[string]int{},
		names:     map[string]int{},
		pq:        map[PQStatus]int{},
		findings:  map[string]*FindingCount{},
		aggs:      map[aggKey]*aggEntry{},
	}
}

// Add folds one record into the summary.
func (a *Accumulator) Add(r *Record) {
	a.s.Flows++
	a.addAggregate(r)
	if a.s.FirstSeen.IsZero() || r.FirstSeen.Before(a.s.FirstSeen) {
		a.s.FirstSeen = r.FirstSeen
	}
	if r.LastSeen.After(a.s.LastSeen) {
		a.s.LastSeen = r.LastSeen
	}

	if r.ServerObserved {
		a.s.ServerObserved++
		a.versions[r.Version]++
		a.ciphers[r.CipherSuite]++
		if r.Group != "" {
			a.groups[r.Group]++
		}
		// Readiness is only meaningful where a negotiation was seen.
		a.pqDecided++
		if r.PQ == PQNegotiated {
			a.pqDone++
		}
	} else {
		a.versions[r.VersionOffered+" (offered)"]++
	}

	if r.ALPN != "" {
		a.alpn[r.ALPN]++
	}
	if r.Transport != "" {
		a.transport[r.Transport]++
	}
	if r.JA4 != "" {
		a.ja4[r.JA4]++
	}
	if r.ECH {
		a.s.ECHOffered++
	}
	// Counted either way. Excluding ECH flows discarded real hostnames,
	// because the extension is usually GREASE and the name usually genuine.
	if r.ServerName != "" {
		a.names[r.ServerName]++
	}
	a.pq[r.PQ]++

	for _, f := range r.Findings {
		fc, ok := a.findings[f.ID]
		if !ok {
			fc = &FindingCount{ID: f.ID, Severity: f.Severity, Example: f.Detail}
			a.findings[f.ID] = fc
		}
		// Keep the highest severity seen for an ID; the same rule can fire
		// at different severities depending on context.
		if severityRank[f.Severity] > severityRank[fc.Severity] {
			fc.Severity = f.Severity
			fc.Example = f.Detail
		}
		fc.Count++
	}
}

// Summary finalises and returns the roll-up. topN bounds each distribution;
// pass 0 for no limit.
func (a *Accumulator) Summary(topN int) Summary {
	s := a.s
	s.Versions = rank(a.versions, topN)
	s.Ciphers = rank(a.ciphers, topN)
	s.Groups = rank(a.groups, topN)
	s.ALPN = rank(a.alpn, topN)
	s.Transports = rank(a.transport, 0)
	s.JA4 = rank(a.ja4, topN)
	s.ServerName = rank(a.names, topN)

	pq := map[string]int{}
	for k, v := range a.pq {
		pq[string(k)] = v
	}
	s.PQ = rank(pq, 0)
	if a.pqDecided > 0 {
		s.PQReadiness = float64(a.pqDone) / float64(a.pqDecided)
	}

	for _, agg := range a.Aggregates(0) {
		if agg.ECHLikelyGREASE {
			s.ECHLikelyGREASE += agg.Count
		}
	}
	s.DistinctFindings = len(a.aggs)
	s.AggregatesDropped = a.aggDropped
	s.Findings = make([]FindingCount, 0, len(a.findings))
	for _, fc := range a.findings {
		s.Findings = append(s.Findings, *fc)
	}
	sort.Slice(s.Findings, func(i, j int) bool {
		ri, rj := severityRank[s.Findings[i].Severity], severityRank[s.Findings[j].Severity]
		if ri != rj {
			return ri > rj
		}
		if s.Findings[i].Count != s.Findings[j].Count {
			return s.Findings[i].Count > s.Findings[j].Count
		}
		return s.Findings[i].ID < s.Findings[j].ID
	})
	return s
}

// rank sorts a distribution by descending count, then by name so that
// output is deterministic and diffable across runs.
func rank(m map[string]int, topN int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		if k == "" {
			continue
		}
		out = append(out, Count{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if topN > 0 && len(out) > topN {
		out = out[:topN]
	}
	return out
}
