package ports

import "github.com/sy-software/minerva-shield/internal/core/domain"

// APIProxy is a reverse proxy server
type APIProxy interface {
	// Call passes the request into the destination server
	Call(request domain.Request) error
}

// TokenValidator validates an authentication token
type TokenValidator interface {
	// Validate checks the provided token and extract user information
	Validate(token string) (domain.User, error)
	// ValidateUse checks the token that must contain a matching "use" claim
	// it also extracts user information
	ValidateUse(token string, use string) (domain.User, error)
}
