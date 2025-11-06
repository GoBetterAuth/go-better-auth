package auth

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/GoBetterAuth/go-better-auth/domain"
)

func (s *Service) buildVerificationURL(token string, callbackURL *string) string {
	if s == nil || s.config == nil {
		return ""
	}

	baseURL := strings.TrimSuffix(s.config.BaseURL, "/")

	basePath := strings.TrimSpace(s.config.BasePath)
	if basePath == "" {
		basePath = domain.DefaultBasePath
	}
	basePath = "/" + strings.Trim(basePath, "/")

	verifyURL := fmt.Sprintf("%s%s/verify-email?token=%s", baseURL, basePath, url.QueryEscape(token))
	if callbackURL != nil && *callbackURL != "" {
		verifyURL += "&callbackURL=" + url.QueryEscape(*callbackURL)
	}

	return verifyURL
}
