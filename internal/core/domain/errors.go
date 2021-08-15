package domain

import "errors"

var (
	ErrNotFound          = errors.New("not_found")
	ErrInvalidAuthHeader = errors.New("invalid_auth_header")
	ErrUnauthorized      = errors.New("unauthorized")
	ErrInternalServer    = errors.New("internal_server_error")
	ErrExpiredToken      = errors.New("expired_token")
	ErrInvalidToken      = errors.New("invalid_token")
	ErrNoUsrInToken      = errors.New("no_user_in_token")
	ErrInvalidTokenUse   = errors.New("invalid_token_use")
)
