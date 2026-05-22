package namesilo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/qdm12/ddns-updater/internal/models"
	"github.com/qdm12/ddns-updater/internal/provider/constants"
	"github.com/qdm12/ddns-updater/internal/provider/errors"
	"github.com/qdm12/ddns-updater/internal/provider/headers"
	"github.com/qdm12/ddns-updater/internal/provider/utils"
	"github.com/qdm12/ddns-updater/pkg/publicip/ipversion"
)

type Provider struct {
	domain     string
	owner      string
	ipVersion  ipversion.IPVersion
	ipv6Suffix netip.Prefix
	key        string
	ttl        *uint32
	cleanup    bool
}

type apiResponse struct {
	Reply struct {
		Code    json.Number `json:"code"`
		Detail  string      `json:"detail"`
		Records []struct {
			ID    string `json:"record_id"`
			Type  string `json:"type"`
			Host  string `json:"host"`
			Value string `json:"value"`
		} `json:"resource_record,omitempty"` // Field only available during list record
	} `json:"reply"`
}

func New(data json.RawMessage, domain, owner string,
	ipVersion ipversion.IPVersion, ipv6Suffix netip.Prefix) (
	provider *Provider, err error,
) {
	var providerSpecificSettings struct {
		Key string  `json:"key"`
		TTL *uint32 `json:"ttl,omitempty"`
		// Cleanup, when true, makes the updater proactively prune stale
		// A/AAAA records for this host. See StaleRecordCleanup.
		Cleanup bool `json:"cleanup,omitempty"`
	}
	err = json.Unmarshal(data, &providerSpecificSettings)
	if err != nil {
		return nil, fmt.Errorf("json decoding provider specific settings: %w", err)
	}

	err = validateSettings(domain, providerSpecificSettings.Key, providerSpecificSettings.TTL)
	if err != nil {
		return nil, fmt.Errorf("validating provider specific settings: %w", err)
	}

	return &Provider{
		domain:     domain,
		owner:      owner,
		ipVersion:  ipVersion,
		ipv6Suffix: ipv6Suffix,
		key:        providerSpecificSettings.Key,
		ttl:        providerSpecificSettings.TTL,
		cleanup:    providerSpecificSettings.Cleanup,
	}, nil
}

// StaleRecordCleanup reports whether the updater should aggressively reconcile
// this host down to a single record on every cycle, even when the public IP is
// already present among the resolved records.
//
// By default the updater treats a host as "up to date" the moment the public IP
// appears in the DNS answer — so if extra A/AAAA records linger (e.g. created by
// older buggy clients, or a manual edit), they are never noticed and never
// pruned. With cleanup enabled, the update Service detects "more records resolve
// than the single one we manage" and forces this provider's Update to run, which
// reconciles the host to exactly one record (see Update). It is opt-in because a
// host may legitimately have multiple records (round-robin); turning it on tells
// the updater "this host must resolve to exactly one record, prune the rest".
//
// This is consumed via an optional interface in internal/update so the Provider
// interface stays unchanged for the ~60 providers that don't implement it.
func (p *Provider) StaleRecordCleanup() bool {
	return p.cleanup
}

func validateSettings(domain, key string, ttl *uint32) (err error) {
	err = utils.CheckDomain(domain)
	if err != nil {
		return fmt.Errorf("%w: %w", errors.ErrDomainNotValid, err)
	}

	const (
		minTTL = uint32(3600)
		maxTTL = uint32(2592001)
	)
	switch {
	case key == "":
		return fmt.Errorf("%w", errors.ErrAPIKeyNotSet)
	case ttl != nil && *ttl < minTTL:
		return fmt.Errorf("%w: %d must be at least %d", errors.ErrTTLTooLow, *ttl, minTTL)
	case ttl != nil && *ttl > maxTTL:
		return fmt.Errorf("%w: %d must be at most %d", errors.ErrTTLTooHigh, *ttl, maxTTL)
	}
	return nil
}

func (p *Provider) String() string {
	return utils.ToString(p.domain, p.owner, constants.NameSilo, p.ipVersion)
}

func (p *Provider) Domain() string {
	return p.domain
}

func (p *Provider) Owner() string {
	return p.owner
}

func (p *Provider) IPVersion() ipversion.IPVersion {
	return p.ipVersion
}

func (p *Provider) IPv6Suffix() netip.Prefix {
	return p.ipv6Suffix
}

func (p *Provider) Proxied() bool {
	return false
}

func (p *Provider) BuildDomainName() string {
	return utils.BuildDomainName(p.owner, p.domain)
}

func (p *Provider) HTML() models.HTMLRow {
	return models.HTMLRow{
		Domain:    fmt.Sprintf("<a href=\"http://%s\">%s</a>", p.BuildDomainName(), p.BuildDomainName()),
		Owner:     p.Owner(),
		Provider:  "<a href=\"https://www.namesilo.com/\">NameSilo</a>",
		IPVersion: p.ipVersion.String(),
	}
}

type matchedRecord struct {
	ID    string
	Value string
}

// Update reconciles NameSilo's records for (host, type) to a single record
// pointing at newIP. The state-machine is:
//
//  1. no record           -> create it
//  2. one record, IP ok   -> no-op
//  3. one record, IP off  -> update in place
//  4. multiple records    -> keep one, delete the rest, then update if needed
//
// Case (4) is the self-healing path: an earlier version of this provider, or
// any out-of-band edit, could leave behind a stale A/AAAA record at the same
// host. Every reconcile run now converges to exactly one managed record.
func (p *Provider) Update(ctx context.Context, client *http.Client, newIP netip.Addr) (netip.Addr, error) {
	recordType := constants.A
	if newIP.Is6() {
		recordType = constants.AAAA
	}

	records, err := p.getRecords(ctx, client, recordType)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("retrieving records: %w", err)
	}

	if len(records) == 0 {
		if err := p.createRecord(ctx, client, recordType, newIP); err != nil {
			return netip.Addr{}, fmt.Errorf("creating record: %w", err)
		}
		return newIP, nil
	}

	// Pick a winner. If any existing record already has the target IP, keep
	// that one so we can no-op without an unnecessary update API call.
	keep := records[0]
	for _, r := range records {
		if ip, parseErr := netip.ParseAddr(r.Value); parseErr == nil && ip == newIP {
			keep = r
			break
		}
	}

	for _, r := range records {
		if r.ID == keep.ID {
			continue
		}
		if err := p.deleteRecord(ctx, client, r.ID); err != nil {
			return netip.Addr{}, fmt.Errorf("deleting duplicate record %s: %w", r.ID, err)
		}
	}

	currentIP, err := netip.ParseAddr(keep.Value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parsing existing IP: %w", err)
	}
	if currentIP == newIP {
		return newIP, nil
	}
	if err := p.updateRecord(ctx, client, keep.ID, newIP); err != nil {
		return netip.Addr{}, fmt.Errorf("updating record: %w", err)
	}
	return newIP, nil
}

// hostMatches reports whether a host field from dnsListRecords belongs to this
// provider's (owner, domain).
//
// NameSilo's dnsListRecords returns the *relative* host — i.e. just the owner
// label ("vpn"), or "" for the apex — NOT the fully-qualified name. Comparing
// the relative host against a synthesized FQDN ("vpn.example.com") therefore
// never matched, so getRecords found nothing, the updater fell through to
// dnsAddRecord, and NameSilo either created a duplicate (when the public IP was
// new) or rejected the add as "already exists". This was the real root cause of
// the duplicate-record bug.
//
// We compare against the relative owner (mapping the apex "@" to ""), and still
// accept the fully-qualified form defensively in case the API ever returns it.
// Both comparisons are case-insensitive and tolerate a trailing dot.
func (p *Provider) hostMatches(recordHost string) bool {
	recordHost = strings.TrimSuffix(strings.ToLower(recordHost), ".")
	owner := strings.ToLower(p.owner)
	if owner == "@" {
		owner = ""
	}
	fqdn := strings.TrimSuffix(strings.ToLower(p.BuildDomainName()), ".")
	return recordHost == owner || recordHost == fqdn
}

// getRecords returns every record matching (host, type). An empty slice with a
// nil error means "no matches" — callers should treat this as the create case
// rather than relying on a sentinel ErrRecordNotFound.
//
// https://www.namesilo.com/api-reference#dns/dns-list-records
func (p *Provider) getRecords(ctx context.Context, client *http.Client, recordType string) (
	records []matchedRecord, err error,
) {
	queryParams := url.Values{}
	requestURL := p.createRequestURL("/api/dnsListRecords", queryParams)

	response, err := p.sendAPIRequest(ctx, client, requestURL)
	if err != nil {
		return nil, err
	}

	for _, record := range response.Reply.Records {
		if !p.hostMatches(record.Host) || record.Type != recordType {
			continue
		}
		records = append(records, matchedRecord{ID: record.ID, Value: record.Value})
	}
	return records, nil
}

// https://www.namesilo.com/api-reference#dns/dns-add-record
func (p *Provider) createRecord(
	ctx context.Context,
	client *http.Client,
	recordType string,
	ip netip.Addr,
) error {
	const path = "/api/dnsAddRecord"
	queryParams := p.buildRecordParams(ip)
	queryParams.Set("rrtype", recordType)

	url := p.createRequestURL(path, queryParams)

	_, err := p.sendAPIRequest(ctx, client, url)
	return err
}

// https://www.namesilo.com/api-reference#dns/dns-update-record
func (p *Provider) updateRecord(
	ctx context.Context,
	client *http.Client,
	recordID string,
	ip netip.Addr,
) error {
	const path = "/api/dnsUpdateRecord"
	queryParams := p.buildRecordParams(ip)
	queryParams.Set("rrid", recordID)

	url := p.createRequestURL(path, queryParams)

	_, err := p.sendAPIRequest(ctx, client, url)
	return err
}

// https://www.namesilo.com/api-reference#dns/dns-delete-record
func (p *Provider) deleteRecord(
	ctx context.Context,
	client *http.Client,
	recordID string,
) error {
	const path = "/api/dnsDeleteRecord"
	queryParams := url.Values{}
	queryParams.Set("rrid", recordID)

	url := p.createRequestURL(path, queryParams)

	_, err := p.sendAPIRequest(ctx, client, url)
	return err
}

// Create and populate common query params for requests that modify a single record (ie. add or update).
func (p *Provider) buildRecordParams(ip netip.Addr) url.Values {
	name := p.owner
	if name == "@" {
		name = ""
	}

	queryParams := url.Values{
		"rrhost":  {name},
		"rrvalue": {ip.String()},
	}
	if p.ttl != nil {
		queryParams.Set("rrttl", strconv.FormatUint(uint64(*p.ttl), 10))
	}

	return queryParams
}

func (p *Provider) createRequestURL(path string, queryParams url.Values) string {
	baseURL := url.URL{
		Scheme: "https",
		Host:   "www.namesilo.com",
		Path:   path,
	}
	queryParams.Set("version", "1")
	queryParams.Set("type", "json")
	queryParams.Set("key", p.key)
	queryParams.Set("domain", p.domain)
	baseURL.RawQuery = queryParams.Encode()
	return baseURL.String()
}

func (p *Provider) sendAPIRequest(ctx context.Context, client *http.Client, url string) (*apiResponse, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating http request: %w", err)
	}
	headers.SetUserAgent(request)

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	data, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %d: %s",
			errors.ErrHTTPStatusNotValid, response.StatusCode, utils.ToSingleLine(string(data)))
	}

	var parsedResponse apiResponse
	err = json.Unmarshal(data, &parsedResponse)
	if err != nil {
		return nil, fmt.Errorf("json decoding response body: %w", err)
	}

	err = p.validateResponseCode(parsedResponse.Reply.Code, parsedResponse.Reply.Detail)
	if err != nil {
		return nil, fmt.Errorf("validating reply code: %w", err)
	}
	return &parsedResponse, nil
}

// https://www.namesilo.com/api-reference (Response Codes)
func (p *Provider) validateResponseCode(code json.Number, detail string) error {
	// The API inconsistently swaps between number and string typing for the code field,
	// but the value should always be an integer.
	parsedCode, err := code.Int64()
	if err != nil {
		return fmt.Errorf("parsing response code: %w", err)
	}

	codeToError := map[int64]error{
		300: nil,                          // Successful API operation
		110: errors.ErrKeyNotValid,        // Invalid API key
		112: errors.ErrFeatureUnavailable, // API not available to Sub-Accounts
		113: errors.ErrBannedAbuse,        // API account cannot be accessed from your IP
		200: errors.ErrDomainDisabled,     // Domain is not active, or does not belong to this user
		201: errors.ErrDNSServerSide,      // Internal system error
		210: errors.ErrUnsuccessful,       // General error (details in response)
		280: errors.ErrBadRequest,         // DNS modification error
	}

	if err, exists := codeToError[parsedCode]; exists {
		if err == nil {
			return nil // Successful operation, no error to return
		}
		return fmt.Errorf("%w: %d: %s", err, parsedCode, detail)
	}

	return fmt.Errorf("%w: %d: %s", errors.ErrUnknownResponse, parsedCode, detail)
}
