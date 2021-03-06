package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"github.com/sy-software/minerva-shield/internal/core/domain"
	"github.com/sy-software/minerva-shield/internal/core/ports"
)

type RestHandler struct {
	config  *domain.Config
	service ports.ProxyService
}

func NewRestHandler(config *domain.Config, service ports.ProxyService) *RestHandler {
	return &RestHandler{
		config:  config,
		service: service,
	}
}

func (handler *RestHandler) CallProxy(c *gin.Context) (domain.Request, error) {
	req, err := handler.service.Authorize(domain.Request{
		Scheme:  c.Request.URL.Scheme,
		Host:    c.Request.Host,
		Path:    c.Request.URL.Path,
		Query:   c.Request.URL.RawQuery,
		Body:    c.Request.Body,
		Method:  c.Request.Method,
		Headers: c.Request.Header,
	})

	if err != nil {
		log.Error().Err(err).Msg("Request is not valid:")
		code := errorToStatusCode(err)
		if code == http.StatusInternalServerError {
			c.JSON(code, gin.H{"error": "internal server error"})
		} else {
			c.JSON(code, gin.H{"error": err.Error()})
		}

		return req, err
	}

	log.Info().Msg("Preparing call to underlaying service")
	log.Debug().Msgf("New request: %+v", req)
	proxy, err := handler.service.Pass(req)

	if err != nil {
		log.Error().Err(err).Strs(domain.REQUEST_ID_HEADER, req.Headers[domain.REQUEST_ID_HEADER]).Msg("Request is not valid:")
		code := errorToStatusCode(err)
		if code == http.StatusInternalServerError {
			c.JSON(code, gin.H{"error": "internal server error"})
		} else {
			c.JSON(code, gin.H{"error": err.Error()})
		}

		return req, err
	}

	log.Info().Msg("Calling underlaying service")
	proxy.ServeHTTP(c.Writer, c.Request)

	return req, nil
}

func errorToStatusCode(e error) int {
	switch e {
	case domain.ErrExpiredToken:
		return http.StatusNotAcceptable
	case domain.ErrInvalidTokenUse:
		return http.StatusNotAcceptable
	case domain.ErrInvalidToken:
		return http.StatusNotAcceptable
	case domain.ErrNoUsrInToken:
		return http.StatusNotAcceptable
	case domain.ErrNotFound:
		return http.StatusNotFound
	case domain.ErrInvalidAuthHeader:
		return http.StatusNotAcceptable
	case domain.ErrUnauthorized:
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}
