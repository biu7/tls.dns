package dnspod

import (
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	tlsdns "github.com/caddyserver/tls.dns"
	"github.com/go-acme/lego/v3/challenge"
	"github.com/go-acme/lego/v3/providers/dns/dnspod"
)

func init() {
	caddy.RegisterModule(DNSPod{})
}

// CaddyModule returns the Caddy module information.
func (DNSPod) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.dns.dnspod",
		New: func() caddy.Module { return new(DNSPod) },
	}
}

// DNSPod configures a solver for the ACME DNS challenge.
type DNSPod struct {
	// An authentication token from your account.
	LoginToken string `json:"auth_token,omitempty"`

	tlsdns.CommonConfig
}

// NewDNSProvider returns a DNS challenge solver.
func (wrapper DNSPod) NewDNSProvider() (challenge.Provider, error) {
	cfg := dnspod.NewDefaultConfig()
	if wrapper.LoginToken != "" {
		cfg.LoginToken = wrapper.LoginToken
	}
	if wrapper.CommonConfig.TTL != 0 {
		cfg.TTL = wrapper.CommonConfig.TTL
	}
	if wrapper.CommonConfig.PropagationTimeout != 0 {
		cfg.PropagationTimeout = time.Duration(wrapper.CommonConfig.PropagationTimeout)
	}
	if wrapper.CommonConfig.PollingInterval != 0 {
		cfg.PollingInterval = time.Duration(wrapper.CommonConfig.PollingInterval)
	}
	if wrapper.CommonConfig.HTTPClient != nil {
		cfg.HTTPClient = wrapper.CommonConfig.HTTPClient.HTTPClient()
	}
	return dnspod.NewDNSProviderConfig(cfg)
}

// Interface guard
var _ caddytls.DNSProviderMaker = (*DNSPod)(nil)
