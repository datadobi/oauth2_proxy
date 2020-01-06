package providers

import (
	"context"
	"fmt"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"net/http"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/requests"
)

// ZenDeskProvider represents a ZenDesk based Identity Provider
type ZenDeskProvider struct {
	*ProviderData
}

// NewZenDeskProvider initiates a new ZenDeskProvider
func NewZenDeskProvider(p *ProviderData) *ZenDeskProvider {
	p.ProviderName = "ZenDesk"

	if p.Scope == "" {
		p.Scope = "read"
	}
	return &ZenDeskProvider{ProviderData: p}
}

func (p *ZenDeskProvider) SetSubdomain(subdomain string) {
	host := fmt.Sprintf("%s.zendesk.com", subdomain)

	if p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{Scheme: "https",
			Host: host,
			Path: "/oauth/authorizations/new"}
	}
	if p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{Scheme: "https",
			Host: host,
			Path: "/oauth/tokens"}
	}
	if p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{Scheme: "https",
			Host: host,
			Path: "/api/v2/users/me.json"}
	}
	if p.ValidateURL.String() == "" {
		p.ValidateURL = p.ProfileURL
	}
}

func makeZenDeskHeader(accessToken string) http.Header {
	return makeAuthorizationHeader(tokenTypeBearer, accessToken, nil)
}

// GetEmailAddress returns the Account email address
func (p *ZenDeskProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	requestURL := p.ValidateURL.String()
	json, err := requests.New(requestURL).
		WithContext(ctx).
		WithHeaders(makeZenDeskHeader(s.AccessToken)).
		Do().
		UnmarshalJSON()

	if err != nil {
		logger.Printf("failed making request %s", err)
		return "", err
	}

	return json.Get("user").Get("email").String()
}
