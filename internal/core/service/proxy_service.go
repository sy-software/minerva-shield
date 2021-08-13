package service

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/google/uuid"
	"github.com/sy-software/minerva-shield/internal/core/domain"
	"github.com/sy-software/minerva-shield/internal/core/ports"
)

const BEARER_REGEX = "^Bearer (.+)$"

var (
	ErrNotFound          = errors.New("not_found")
	ErrInvalidAuthHeader = errors.New("invalid_auth_header")
	ErrUnauthorized      = errors.New("unauthorized")
	ErrInternalServer    = errors.New("internal_server_error")
)

var RESERVED_HEADERS = []string{
	domain.REQUEST_ID_HEADER,
	domain.USER_INFO_HEADER,
	domain.TOKEN_USE_HEADER,
}

type ProxyService struct {
	config            *domain.Config
	externalValidator ports.TokenValidator
	internalValidator ports.TokenValidator
}

func NewProxyService(
	config *domain.Config,
	externalValidator ports.TokenValidator,
	internalValidator ports.TokenValidator) *ProxyService {
	return &ProxyService{
		config:            config,
		externalValidator: externalValidator,
		internalValidator: internalValidator,
	}
}

func (proxy *ProxyService) Authorize(request domain.Request) (domain.Request, error) {
	route, ok := proxy.config.RouteTable[request.Path]

	if !ok {
		return request, ErrNotFound
	}

	newHeaders := request.Headers

	// Clear all reserved headers
	// TODO: Apply header allow list to remove any extraneous header
	for _, header := range RESERVED_HEADERS {
		delete(newHeaders, header)
	}

	newHeaders.Add(domain.REQUEST_ID_HEADER, uuid.New().String())

	// Authorization not required
	if route.TokenUse == nil && route.TokenValidator == nil {
		return domain.Request{
			Host:    route.Host,
			Path:    route.Path,
			Scheme:  route.Scheme,
			Headers: newHeaders,
			Query:   request.Query,
			Body:    request.Body,
			Method:  request.Method,
		}, nil
	}

	// TODO: Support other token types
	token := request.Headers.Get("Authorization")

	re := regexp.MustCompile(BEARER_REGEX)
	if !re.MatchString(token) {
		return request, ErrInvalidAuthHeader
	}

	groups := re.FindStringSubmatch(token)
	token = groups[1]

	var userInfo domain.User
	var err error
	if *route.TokenValidator == domain.ExternalTokenValidator {
		userInfo, err = proxy.externalValidator.Validate(token)

		if err != nil {
			return request, ErrUnauthorized
		}
	} else if *route.TokenValidator == domain.InternalTokenValidator {

		if route.TokenUse != nil {
			userInfo, err = proxy.internalValidator.ValidateUse(token, *route.TokenUse)
			newHeaders.Set(domain.TOKEN_USE_HEADER, *route.TokenUse)
		} else {
			userInfo, err = proxy.internalValidator.Validate(token)
		}

		if err != nil {
			return request, ErrUnauthorized
		}
	}

	userBytes, err := json.Marshal(userInfo)

	if err != nil {
		return request, ErrInternalServer
	}

	newHeaders.Set(domain.USER_INFO_HEADER, base64.StdEncoding.EncodeToString(userBytes))

	return domain.Request{
		Host:    route.Host,
		Path:    route.Path,
		Scheme:  route.Scheme,
		Headers: newHeaders,
		Query:   request.Query,
		Body:    request.Body,
		Method:  request.Method,
	}, nil
}
