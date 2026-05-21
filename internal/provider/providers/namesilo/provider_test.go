package namesilo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qdm12/ddns-updater/pkg/publicip/ipversion"
)

func Test_hostMatches(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		recordHost   string
		expectedHost string
		match        bool
	}{
		"exact":              {"vpn.example.com", "vpn.example.com", true},
		"trailing_dot":       {"vpn.example.com.", "vpn.example.com", true},
		"uppercase":          {"VPN.Example.com", "vpn.example.com", true},
		"different":          {"other.example.com", "vpn.example.com", false},
		"different_suffix":   {"vpn.example.net", "vpn.example.com", false},
		"empty_vs_anything":  {"", "vpn.example.com", false},
		"both_empty":         {"", "", true},
		"trailing_dot_both":  {"vpn.example.com.", "vpn.example.com.", true},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.match, hostMatches(tc.recordHost, tc.expectedHost))
		})
	}
}

// stubServer fakes the NameSilo HTTP API so we can drive Update() through every
// arm of the reconcile state machine without touching the network. Each request
// path it has a handler for is counted, and dnsListRecords serves whatever is in
// the records slice at call time — mutations apply to that slice so subsequent
// calls (e.g. a follow-up dnsListRecords) would see the updated state.
type stubServer struct {
	t       *testing.T
	mu      sync.Mutex
	records []resourceRecord
	calls   map[string]int
	server  *httptest.Server
}

type resourceRecord struct {
	ID    string `json:"record_id"`
	Type  string `json:"type"`
	Host  string `json:"host"`
	Value string `json:"value"`
}

type reply struct {
	Code    string           `json:"code"`
	Detail  string           `json:"detail"`
	Records []resourceRecord `json:"resource_record,omitempty"`
}

func newStub(t *testing.T, records []resourceRecord) *stubServer {
	t.Helper()
	s := &stubServer{
		t:       t,
		records: records,
		calls:   map[string]int{},
	}
	s.server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.server.Close)
	return s
}

func (s *stubServer) callCount(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[path]
}

func (s *stubServer) currentRecords() []resourceRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]resourceRecord, len(s.records))
	copy(out, s.records)
	return out
}

func (s *stubServer) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls[r.URL.Path]++
	q := r.URL.Query()

	switch r.URL.Path {
	case "/api/dnsListRecords":
		writeJSON(s.t, w, reply{Code: "300", Detail: "success", Records: s.records})
	case "/api/dnsAddRecord":
		host := q.Get("rrhost")
		domain := q.Get("domain")
		fqdn := host + "." + domain
		if host == "" {
			fqdn = domain
		}
		s.records = append(s.records, resourceRecord{
			ID:    "new-" + q.Get("rrvalue"),
			Type:  q.Get("rrtype"),
			Host:  fqdn,
			Value: q.Get("rrvalue"),
		})
		writeJSON(s.t, w, reply{Code: "300", Detail: "success"})
	case "/api/dnsUpdateRecord":
		rrid := q.Get("rrid")
		for i := range s.records {
			if s.records[i].ID == rrid {
				s.records[i].Value = q.Get("rrvalue")
				break
			}
		}
		writeJSON(s.t, w, reply{Code: "300", Detail: "success"})
	case "/api/dnsDeleteRecord":
		rrid := q.Get("rrid")
		kept := s.records[:0]
		for _, rec := range s.records {
			if rec.ID != rrid {
				kept = append(kept, rec)
			}
		}
		s.records = kept
		writeJSON(s.t, w, reply{Code: "300", Detail: "success"})
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, r reply) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(struct {
		Reply reply `json:"reply"`
	}{Reply: r})
	require.NoError(t, err)
}

// providerForStub wires a Provider whose API endpoint points at the stub. The
// real createRequestURL hardcodes www.namesilo.com, so we wrap the httptest URL
// into a transport that rewrites the host on outbound requests. Both domain
// and owner are fixed (example.com / vpn) — the failure modes we care about
// live in the (host, type) reconcile logic, not in the routing.
func providerForStub(t *testing.T, stub *stubServer) (*Provider, *http.Client) {
	t.Helper()

	provider, err := New(json.RawMessage(`{"key":"test-key"}`), "example.com", "vpn", ipversion.IP4, netip.Prefix{})
	require.NoError(t, err)

	stubURL, err := url.Parse(stub.server.URL)
	require.NoError(t, err)

	client := &http.Client{
		Transport: rewriteTransport{
			target: stubURL,
			inner:  http.DefaultTransport,
		},
	}
	return provider, client
}

type rewriteTransport struct {
	target *url.URL
	inner  http.RoundTripper
}

func (rt rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme = rt.target.Scheme
	req.URL.Host = rt.target.Host
	req.Host = rt.target.Host
	return rt.inner.RoundTrip(req)
}

func Test_Update_creates_record_when_missing(t *testing.T) {
	t.Parallel()

	stub := newStub(t, nil)
	provider, client := providerForStub(t, stub)

	newIP := netip.MustParseAddr("1.1.1.1")
	got, err := provider.Update(context.Background(), client, newIP)
	require.NoError(t, err)
	assert.Equal(t, newIP, got)

	assert.Equal(t, 1, stub.callCount("/api/dnsAddRecord"))
	assert.Equal(t, 0, stub.callCount("/api/dnsUpdateRecord"))
	assert.Equal(t, 0, stub.callCount("/api/dnsDeleteRecord"))

	current := stub.currentRecords()
	require.Len(t, current, 1)
	assert.Equal(t, "vpn.example.com", current[0].Host)
	assert.Equal(t, "1.1.1.1", current[0].Value)
}

func Test_Update_updates_existing_record_on_ip_change(t *testing.T) {
	t.Parallel()

	stub := newStub(t, []resourceRecord{{
		ID: "abc", Type: "A", Host: "vpn.example.com", Value: "1.1.1.1",
	}})
	provider, client := providerForStub(t, stub)

	newIP := netip.MustParseAddr("1.1.1.2")
	got, err := provider.Update(context.Background(), client, newIP)
	require.NoError(t, err)
	assert.Equal(t, newIP, got)

	assert.Equal(t, 1, stub.callCount("/api/dnsUpdateRecord"))
	assert.Equal(t, 0, stub.callCount("/api/dnsAddRecord"))
	assert.Equal(t, 0, stub.callCount("/api/dnsDeleteRecord"))

	current := stub.currentRecords()
	require.Len(t, current, 1)
	assert.Equal(t, "1.1.1.2", current[0].Value)
}

// Test_Update_deletes_duplicates_left_by_old_buggy_versions guards against the
// reported regression: WAN-IP flap left a stale A record behind alongside the
// new one. The reconciler must converge to a single record on the next run.
func Test_Update_deletes_duplicates_left_by_old_buggy_versions(t *testing.T) {
	t.Parallel()

	stub := newStub(t, []resourceRecord{
		{ID: "old", Type: "A", Host: "vpn.example.com", Value: "1.1.1.1"},
		{ID: "new", Type: "A", Host: "vpn.example.com", Value: "1.1.1.2"},
	})
	provider, client := providerForStub(t, stub)

	newIP := netip.MustParseAddr("1.1.1.2")
	got, err := provider.Update(context.Background(), client, newIP)
	require.NoError(t, err)
	assert.Equal(t, newIP, got)

	assert.Equal(t, 1, stub.callCount("/api/dnsDeleteRecord"))
	assert.Equal(t, 0, stub.callCount("/api/dnsAddRecord"))
	assert.Equal(t, 0, stub.callCount("/api/dnsUpdateRecord"))

	current := stub.currentRecords()
	require.Len(t, current, 1)
	assert.Equal(t, "new", current[0].ID)
	assert.Equal(t, "1.1.1.2", current[0].Value)
}

func Test_Update_noop_when_record_already_correct(t *testing.T) {
	t.Parallel()

	stub := newStub(t, []resourceRecord{{
		ID: "abc", Type: "A", Host: "vpn.example.com", Value: "1.1.1.1",
	}})
	provider, client := providerForStub(t, stub)

	newIP := netip.MustParseAddr("1.1.1.1")
	got, err := provider.Update(context.Background(), client, newIP)
	require.NoError(t, err)
	assert.Equal(t, newIP, got)

	assert.Equal(t, 0, stub.callCount("/api/dnsUpdateRecord"))
	assert.Equal(t, 0, stub.callCount("/api/dnsAddRecord"))
	assert.Equal(t, 0, stub.callCount("/api/dnsDeleteRecord"))
}

func Test_Update_matches_host_with_trailing_dot_or_case_quirks(t *testing.T) {
	t.Parallel()

	stub := newStub(t, []resourceRecord{{
		ID: "abc", Type: "A", Host: "VPN.Example.com.", Value: "1.1.1.1",
	}})
	provider, client := providerForStub(t, stub)

	newIP := netip.MustParseAddr("1.1.1.2")
	got, err := provider.Update(context.Background(), client, newIP)
	require.NoError(t, err)
	assert.Equal(t, newIP, got)

	assert.Equal(t, 1, stub.callCount("/api/dnsUpdateRecord"))
	assert.Equal(t, 0, stub.callCount("/api/dnsAddRecord"),
		"a host string mismatch must NOT cause a duplicate add")
}

func Test_Update_deletes_extras_and_updates_when_no_existing_matches_newIP(t *testing.T) {
	t.Parallel()

	stub := newStub(t, []resourceRecord{
		{ID: "stale-a", Type: "A", Host: "vpn.example.com", Value: "1.1.1.1"},
		{ID: "stale-b", Type: "A", Host: "vpn.example.com", Value: "5.5.5.5"},
	})
	provider, client := providerForStub(t, stub)

	newIP := netip.MustParseAddr("1.1.1.2")
	got, err := provider.Update(context.Background(), client, newIP)
	require.NoError(t, err)
	assert.Equal(t, newIP, got)

	assert.Equal(t, 1, stub.callCount("/api/dnsDeleteRecord"))
	assert.Equal(t, 1, stub.callCount("/api/dnsUpdateRecord"))

	current := stub.currentRecords()
	require.Len(t, current, 1)
	assert.Equal(t, "1.1.1.2", current[0].Value)
}

func Test_Update_ignores_unrelated_records(t *testing.T) {
	t.Parallel()

	stub := newStub(t, []resourceRecord{
		{ID: "mx", Type: "MX", Host: "example.com", Value: "mail.example.com"},
		{ID: "other", Type: "A", Host: "other.example.com", Value: "9.9.9.9"},
	})
	provider, client := providerForStub(t, stub)

	newIP := netip.MustParseAddr("1.1.1.1")
	_, err := provider.Update(context.Background(), client, newIP)
	require.NoError(t, err)

	assert.Equal(t, 1, stub.callCount("/api/dnsAddRecord"))
	assert.Equal(t, 0, stub.callCount("/api/dnsDeleteRecord"))

	hosts := []string{}
	for _, r := range stub.currentRecords() {
		hosts = append(hosts, r.Host+"="+r.Value)
	}
	sort.Strings(hosts)
	assert.Equal(t, []string{
		"example.com=mail.example.com",
		"other.example.com=9.9.9.9",
		"vpn.example.com=1.1.1.1",
	}, hosts)
}
