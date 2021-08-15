package mocks

import "github.com/sy-software/minerva-shield/internal/core/domain"

type ApiProxy struct{}

func (proxy *ApiProxy) Call(request domain.Request) (domain.Proxy, error) {
	return nil, nil
}
