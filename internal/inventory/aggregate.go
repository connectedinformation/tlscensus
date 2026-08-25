package inventory

import (
	"net/netip"
	"sort"
	"time"
)

// An inventory is a set, not a log.
//
// A browser opens several connections to one host with byte-identical
// parameters, so a per-handshake view answers the same question repeatedly:
// seven rows for cloudflare.com that differ only in client port and
// millisecond. Aggregating on what makes two handshakes the same *finding*
// turns that into one row with a count and a time range, which is both
// shorter and more informative — and it bounds memory for a capture that
// never ends, where retaining every event does not.
//
// The event view is still available: `-o ndjson` streams one record per
// handshake and retains nothing, which is what a log shipper wants.

// maxAggregates caps distinct findings retained. Aggregates grow far slower
// than events — a host contacts orders of magnitude fewer distinct
// (destination, parameters) tuples than it opens connections — but a long
// enough run on a busy network still accumulates, so there is a limit, and
// what it drops is counted rather than silently discarded.
const maxAggregates = 20000

// maxTrackedClients bounds the distinct-client set per aggregate. On an
// endpoint this is always one; on a mirror port it is the whole network, and
// an exact count is not worth unbounded memory.
const maxTrackedClients = 256

// Aggregate is one distinct finding: a destination and the cryptography
// negotiated with it, however many times that happened.
type Aggregate struct {
	Transport  string     `json:"transport"`
	ServerName string     `json:"server_name,omitempty"`
	ServerIP   netip.Addr `json:"server_ip"`
	ServerPort uint16     `json:"server_port"`

	Version     string `json:"version,omitempty"`
	CipherSuite string `json:"cipher_suite,omitempty"`
	Group       string `json:"group,omitempty"`
	ALPN        string `json:"alpn,omitempty"`
	// JA4s are the distinct client fingerprints seen for this finding,
	// capped at maxTrackedClients.
	JA4s []string `json:"ja4s,omitempty"`
	PQ   PQStatus `json:"pq_status"`
	ECH  bool     `json:"ech,omitempty"`
	// ECHConfigIDs is how many distinct config_ids were seen for this
	// destination. More than one, across more than one connection, means
	// the extension was GREASE: a real ECH config has a stable id.
	ECHConfigIDs int `json:"ech_config_ids,omitempty"`
	// ECHLikelyGREASE is that inference. When true the server name is a
	// genuine destination despite the extension being present.
	ECHLikelyGREASE bool `json:"ech_likely_grease,omitempty"`

	ServerObserved bool `json:"server_observed"`

	Count int `json:"count"`
	// Clients is the number of distinct client addresses seen, capped at
	// maxTrackedClients; ClientsCapped says the true number is higher.
	Clients       int  `json:"clients"`
	ClientsCapped bool `json:"clients_capped,omitempty"`

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	Severity Severity `json:"severity"`
	Findings []string `json:"findings,omitempty"`
}

// aggKey is what makes two handshakes the same finding. Client address and
// port are deliberately absent: on a host inventory the client is always the
// same machine, and on a tap the distinct-client count preserves what
// matters without multiplying the rows.
type aggKey struct {
	transport string
	name      string
	port      uint16
	version   string
	cipher    string
	group     string
	alpn      string
	pq        PQStatus
	ech       bool
}

// JA4 is deliberately not part of the key.
//
// It was, and it made the aggregation nearly useless: a host reached with
// several client configurations produced a separate single-count row for
// each, identical in every displayed column, because the fingerprints
// differed invisibly. Client diversity is real information, but it is a
// property *of* a finding rather than what distinguishes one finding from
// another — so it is counted within the aggregate instead.

type aggEntry struct {
	agg       Aggregate
	clients   map[netip.Addr]struct{}
	findings  map[string]struct{}
	ja4s      map[string]struct{}
	echConfig map[uint8]struct{}
}

func keyOf(r *Record) aggKey {
	name := r.ServerName
	if name == "" {
		name = r.ServerIP.String()
	}
	return aggKey{
		transport: r.Transport, name: name, port: r.ServerPort,
		version: r.Version, cipher: r.CipherSuite, group: r.Group,
		alpn: r.ALPN, pq: r.PQ, ech: r.ECH,
	}
}

func (a *Accumulator) addAggregate(r *Record) {
	k := keyOf(r)
	e, ok := a.aggs[k]
	if !ok {
		if len(a.aggs) >= maxAggregates {
			a.aggDropped++
			return
		}
		e = &aggEntry{
			agg: Aggregate{
				Transport: r.Transport, ServerName: r.ServerName,
				ServerIP: r.ServerIP, ServerPort: r.ServerPort,
				Version: r.Version, CipherSuite: r.CipherSuite,
				Group: r.Group, ALPN: r.ALPN,
				PQ: r.PQ, ECH: r.ECH, ServerObserved: r.ServerObserved,
				FirstSeen: r.FirstSeen, LastSeen: r.LastSeen,
			},
			clients:   map[netip.Addr]struct{}{},
			findings:  map[string]struct{}{},
			ja4s:      map[string]struct{}{},
			echConfig: map[uint8]struct{}{},
		}
		a.aggs[k] = e
	}

	e.agg.Count++
	if r.FirstSeen.Before(e.agg.FirstSeen) {
		e.agg.FirstSeen = r.FirstSeen
	}
	if r.LastSeen.After(e.agg.LastSeen) {
		e.agg.LastSeen = r.LastSeen
	}
	if len(e.clients) < maxTrackedClients {
		e.clients[r.ClientIP] = struct{}{}
	} else if _, seen := e.clients[r.ClientIP]; !seen {
		e.agg.ClientsCapped = true
	}
	if r.ECH && len(e.echConfig) < maxTrackedClients {
		e.echConfig[r.ECHConfigID] = struct{}{}
	}
	if r.JA4 != "" && len(e.ja4s) < maxTrackedClients {
		e.ja4s[r.JA4] = struct{}{}
	}
	if sev := r.MaxSeverity(); severityRank[sev] > severityRank[e.agg.Severity] {
		e.agg.Severity = sev
	}
	for _, f := range r.Findings {
		e.findings[f.ID] = struct{}{}
	}
}

// Aggregates returns the distinct findings, worst first. topN bounds the
// result; pass 0 for all.
func (a *Accumulator) Aggregates(topN int) []Aggregate {
	out := make([]Aggregate, 0, len(a.aggs))
	for _, e := range a.aggs {
		agg := e.agg
		agg.Clients = len(e.clients)
		agg.ECHConfigIDs = len(e.echConfig)
		// A stable id across several connections is consistent with a real
		// published config; a varying one is not. One connection proves
		// nothing either way.
		agg.ECHLikelyGREASE = agg.ECH && agg.Count > 1 && agg.ECHConfigIDs > 1
		agg.JA4s = make([]string, 0, len(e.ja4s))
		for f := range e.ja4s {
			agg.JA4s = append(agg.JA4s, f)
		}
		sort.Strings(agg.JA4s)
		agg.Findings = make([]string, 0, len(e.findings))
		for id := range e.findings {
			agg.Findings = append(agg.Findings, id)
		}
		sort.Strings(agg.Findings)
		out = append(out, agg)
	}
	// Worst first, then most frequent, then by name so runs are diffable.
	sort.Slice(out, func(i, j int) bool {
		if ri, rj := severityRank[out[i].Severity], severityRank[out[j].Severity]; ri != rj {
			return ri > rj
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].ServerName != out[j].ServerName {
			return out[i].ServerName < out[j].ServerName
		}
		return out[i].CipherSuite < out[j].CipherSuite
	})
	if topN > 0 && len(out) > topN {
		out = out[:topN]
	}
	return out
}

// AggregatesDropped is how many distinct findings were discarded because
// maxAggregates was reached. Non-zero means the inventory is incomplete.
func (a *Accumulator) AggregatesDropped() int { return a.aggDropped }

// DistinctFindings is the number of aggregates retained.
func (a *Accumulator) DistinctFindings() int { return len(a.aggs) }
