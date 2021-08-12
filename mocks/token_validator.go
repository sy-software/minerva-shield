package mocks

import "github.com/sy-software/minerva-shield/internal/core/domain"

type TokenValidator struct {
	ValidateInterceptor    func(token string) (domain.User, error)
	ValidateUseInterceptor func(token string, use string) (domain.User, error)
}

func (val *TokenValidator) Validate(token string) (domain.User, error) {
	return val.ValidateInterceptor(token)
}

func (val *TokenValidator) ValidateUse(token string, use string) (domain.User, error) {
	return val.ValidateUseInterceptor(token, use)
}
