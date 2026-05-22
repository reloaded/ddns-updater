package update

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/ddns-updater/pkg/publicip/ipversion"
	"github.com/stretchr/testify/assert"
)

type stubResolver struct {
	ips []netip.Addr
}

func (s stubResolver) LookupNetIP(_ context.Context, network, _ string) ([]netip.Addr, error) {
	if network == "ip6" {
		return nil, nil
	}
	return s.ips, nil
}

type noopLogger struct{}

func (noopLogger) Debug(string) {}
func (noopLogger) Info(string)  {}
func (noopLogger) Warn(string)  {}
func (noopLogger) Error(string) {}

func Test_shouldUpdateRecordWithLookup_cleanup(t *testing.T) {
	t.Parallel()

	ip123 := netip.MustParseAddr("174.165.38.123")
	ip128 := netip.MustParseAddr("174.165.38.128")

	testCases := map[string]struct {
		recordIPs []netip.Addr
		publicIP  netip.Addr
		cleanup   bool
		want      bool
	}{
		"up_to_date_single_no_cleanup": {
			recordIPs: []netip.Addr{ip128}, publicIP: ip128, cleanup: false, want: false,
		},
		"up_to_date_single_cleanup": {
			recordIPs: []netip.Addr{ip128}, publicIP: ip128, cleanup: true, want: false,
		},
		"ip_changed_no_cleanup": {
			recordIPs: []netip.Addr{ip123}, publicIP: ip128, cleanup: false, want: true,
		},
		"duplicate_present_no_cleanup_tolerated": {
			recordIPs: []netip.Addr{ip123, ip128}, publicIP: ip128, cleanup: false, want: false,
		},
		"duplicate_present_cleanup_forces_update": {
			recordIPs: []netip.Addr{ip123, ip128}, publicIP: ip128, cleanup: true, want: true,
		},
		"duplicate_all_wrong_updates_regardless": {
			recordIPs: []netip.Addr{ip123, netip.MustParseAddr("174.165.38.99")},
			publicIP:  ip128, cleanup: false, want: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := &Service{
				resolver: stubResolver{ips: tc.recordIPs},
				logger:   noopLogger{},
				timeNow:  time.Now,
			}
			got := s.shouldUpdateRecordWithLookup(context.Background(),
				"vpn.example.com", ipversion.IP4, tc.publicIP, tc.cleanup)
			assert.Equal(t, tc.want, got)
		})
	}
}
