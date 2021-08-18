package service

import (
	"encoding/base64"
	"encoding/json"
	"regexp"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/sy-software/minerva-shield/internal/core/domain"
	"github.com/sy-software/minerva-shield/internal/core/ports"
)

const BEARER_REGEX = "^Bearer (.+)$"

var RESERVED_HEADERS = []string{
	domain.REQUEST_ID_HEADER,
	domain.USER_INFO_HEADER,
	domain.TOKEN_USE_HEADER,
}

type ProxyService struct {
	config            *domain.Config
	proxy             ports.APIProxy
	externalValidator ports.TokenValidator
	internalValidator ports.TokenValidator
}

func NewProxyService(
	config *domain.Config,
	proxy ports.APIProxy,
	externalValidator ports.TokenValidator,
	internalValidator ports.TokenValidator) *ProxyService {
	return &ProxyService{
		config:            config,
		proxy:             proxy,
		externalValidator: externalValidator,
		internalValidator: internalValidator,
	}
}

func (proxy *ProxyService) Authorize(request domain.Request) (domain.Request, error) {
	route, ok := proxy.config.RouteTable[request.Path]

	if !ok {
		return request, domain.ErrNotFound
	}

	newHeaders := request.Headers

	// Clear all reserved headers
	// TODO: Apply header allow list to remove any extraneous header
	for _, header := range RESERVED_HEADERS {
		delete(newHeaders, header)
	}

	reqId := uuid.New().String()
	newHeaders.Add(domain.REQUEST_ID_HEADER, reqId)

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
		log.Error().Msgf("Invalid Authorization header: %s", token)
		return request, domain.ErrInvalidAuthHeader
	}

	groups := re.FindStringSubmatch(token)
	token = groups[1]

	var userInfo domain.User
	var err error
	if *route.TokenValidator == domain.ExternalTokenValidator {
		userInfo, err = proxy.externalValidator.Validate(token)

		if err != nil {
			log.Error().Err(err).Str(domain.REQUEST_ID_HEADER, reqId).Msg("Token vas not validated:")
			return request, domain.ErrUnauthorized
		}
	} else if *route.TokenValidator == domain.InternalTokenValidator {

		if route.TokenUse != nil {
			userInfo, err = proxy.internalValidator.ValidateUse(token, *route.TokenUse)
			newHeaders.Set(domain.TOKEN_USE_HEADER, *route.TokenUse)
		} else {
			userInfo, err = proxy.internalValidator.Validate(token)
		}

		if err != nil {
			log.Error().Err(err).Str(domain.REQUEST_ID_HEADER, reqId).Msg("Token vas not validated:")
			return request, domain.ErrUnauthorized
		}
	}

	userBytes, err := json.Marshal(userInfo)

	if err != nil {
		log.Error().Err(err).Str(domain.REQUEST_ID_HEADER, reqId).Msg("Can't serialize user info:")
		return request, domain.ErrInternalServer
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

func (service *ProxyService) Pass(request domain.Request) (domain.Proxy, error) {
	return service.proxy.Call(request)
}
