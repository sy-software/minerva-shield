package service

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/sy-software/minerva-shield/internal/core/domain"
	"github.com/sy-software/minerva-shield/mocks"
)

func TestRouteWithoutAuthentication(t *testing.T) {
	route := domain.Route{
		Path:           "my/path",
		Host:           "internal.api",
		Scheme:         "http",
		TokenValidator: nil,
		TokenUse:       nil,
	}
	config := domain.DefaultConfig()
	config.RouteTable["my/path"] = route

	request := domain.Request{
		Scheme:  "https",
		Host:    "external.api",
		Path:    "my/path",
		Headers: http.Header{},
	}

	validator := mocks.TokenValidator{
		ValidateInterceptor: func(token string) (domain.User, error) {
			return domain.User{}, errors.New("Validator should not be called")
		},
	}

	service := NewProxyService(&config, &mocks.ApiProxy{}, &validator, &validator)
	got, err := service.Authorize(request)

	if err != nil {
		t.Errorf("Expected authorize without error, got: %v", err)
	}

	if got.Path != route.Path {
		t.Errorf("Expected path to be: %q got: %q", route.Path, got.Path)
	}

	if got.Host != route.Host {
		t.Errorf("Expected host to be: %q got: %q", route.Host, got.Host)
	}

	if got.Scheme != route.Scheme {
		t.Errorf("Expected scheme to be: %q got: %q", route.Scheme, got.Scheme)
	}

	requestId := got.Headers.Get(domain.REQUEST_ID_HEADER)
	if requestId == "" {
		t.Errorf("Expected %q header to be set", domain.REQUEST_ID_HEADER)
	}
}

func TestRouteWithAuthentication(t *testing.T) {
	t.Run("Test Third party Authorization", func(t *testing.T) {
		expected := domain.User{
			Id:       "myId",
			Name:     "Tony Stark",
			Username: "IronMan",
			Picture:  "http://picture.com/ironman",
			Role:     "hero",
			Provider: "StarkIndustries",
			TokenID:  "myTokenID",
		}

		externalCalled := false
		externalValidator := mocks.TokenValidator{
			ValidateInterceptor: func(token string) (domain.User, error) {
				externalCalled = true

				if token != expected.TokenID {
					t.Errorf("Expected validator to be called with token: myToken got: %q", token)
				}
				return expected, nil
			},
			ValidateUseInterceptor: func(token, use string) (domain.User, error) {
				t.Errorf("Expected external use validator to not be called")
				return expected, nil
			},
		}

		internalValidator := mocks.TokenValidator{
			ValidateInterceptor: func(token string) (domain.User, error) {
				t.Errorf("Expected internal validator to not be called")
				return expected, nil
			},
			ValidateUseInterceptor: func(token, use string) (domain.User, error) {
				t.Errorf("Expected internal validator to not be called")
				return expected, nil
			},
		}

		external := domain.ExternalTokenValidator
		route := domain.Route{
			Path:           "my/path",
			Host:           "internal.api",
			Scheme:         "http",
			TokenValidator: &external,
			TokenUse:       nil,
		}
		config := domain.DefaultConfig()
		config.RouteTable["my/path"] = route

		request := domain.Request{
			Scheme: "https",
			Host:   "external.api",
			Path:   "my/path",
			Headers: http.Header{
				"Authorization": []string{fmt.Sprintf("Bearer %s", expected.TokenID)},
			},
		}

		service := NewProxyService(
			&config,
			&mocks.ApiProxy{},
			&externalValidator,
			&internalValidator,
		)
		got, err := service.Authorize(request)

		if err != nil {
			t.Errorf("Expected authorize without error, got: %v", err)
		}

		if !externalCalled {
			t.Errorf("Expected external validator to be called")
		}

		if got.Path != route.Path {
			t.Errorf("Expected path to be: %q got: %q", route.Path, got.Path)
		}

		if got.Host != route.Host {
			t.Errorf("Expected host to be: %q got: %q", route.Host, got.Host)
		}

		if got.Scheme != route.Scheme {
			t.Errorf("Expected scheme to be: %q got: %q", route.Scheme, got.Scheme)
		}

		requestId := got.Headers.Get(domain.REQUEST_ID_HEADER)
		if requestId == "" {
			t.Errorf("Expected %q header to be set", domain.REQUEST_ID_HEADER)
		}

		userInfoStr := got.Headers.Get(domain.USER_INFO_HEADER)
		if userInfoStr == "" {
			t.Errorf("Expected %q header to be set", domain.USER_INFO_HEADER)
		}

		userInfoBytes, err := base64.StdEncoding.DecodeString(userInfoStr)

		if err != nil {
			t.Errorf("Expected base64 decode without error, got: %v", err)
		}

		var userInfo domain.User
		err = json.Unmarshal(userInfoBytes, &userInfo)

		if err != nil {
			t.Errorf("Expected json decode without error, got: %v", err)
		}

		if !cmp.Equal(expected, userInfo) {
			t.Errorf("Expected user info to be: %+v got: %+v", expected, userInfo)
		}
	})

	t.Run("Test JWT Access Authorization", func(t *testing.T) {
		expected := domain.User{
			Id:       "myId",
			Name:     "Tony Stark",
			Username: "IronMan",
			Picture:  "http://picture.com/ironman",
			Role:     "hero",
			Provider: "StarkIndustries",
			TokenID:  "myTokenID",
		}

		internal := domain.InternalTokenValidator
		use := "access"
		route := domain.Route{
			Path:           "my/path",
			Host:           "internal.api",
			Scheme:         "http",
			TokenValidator: &internal,
			TokenUse:       &use,
		}

		externalValidator := mocks.TokenValidator{
			ValidateInterceptor: func(token string) (domain.User, error) {
				t.Errorf("Expected external validator to not be called")
				return expected, nil
			},
			ValidateUseInterceptor: func(token, use string) (domain.User, error) {
				t.Errorf("Expected external validator to not be called")
				return expected, nil
			},
		}

		internalCalled := false
		internalValidator := mocks.TokenValidator{
			ValidateInterceptor: func(token string) (domain.User, error) {
				t.Errorf("Expected internal validator to not be called without use")
				return expected, nil
			},
			ValidateUseInterceptor: func(token string, use string) (domain.User, error) {
				internalCalled = true
				if token != expected.TokenID {
					t.Errorf("Expected validator to be called with token: myToken got: %q", token)
				}

				if use != *route.TokenUse {
					t.Errorf("Expected validator to be called with use: %q got: %q", *route.TokenUse, token)
				}

				return expected, nil
			},
		}

		config := domain.DefaultConfig()
		config.RouteTable["my/path"] = route

		request := domain.Request{
			Scheme: "https",
			Host:   "external.api",
			Path:   "my/path",
			Headers: http.Header{
				"Authorization": []string{fmt.Sprintf("Bearer %s", expected.TokenID)},
			},
		}

		service := NewProxyService(
			&config,
			&mocks.ApiProxy{},
			&externalValidator,
			&internalValidator,
		)
		got, err := service.Authorize(request)

		if err != nil {
			t.Errorf("Expected authorize without error, got: %v", err)
		}

		if !internalCalled {
			t.Errorf("Expected internal validator to be called")
		}

		if got.Path != route.Path {
			t.Errorf("Expected path to be: %q got: %q", route.Path, got.Path)
		}

		if got.Host != route.Host {
			t.Errorf("Expected host to be: %q got: %q", route.Host, got.Host)
		}

		if got.Scheme != route.Scheme {
			t.Errorf("Expected scheme to be: %q got: %q", route.Scheme, got.Scheme)
		}

		requestId := got.Headers.Get(domain.REQUEST_ID_HEADER)
		if requestId == "" {
			t.Errorf("Expected %q header to be set", domain.REQUEST_ID_HEADER)
		}

		tokenUse := got.Headers.Get(domain.TOKEN_USE_HEADER)
		if tokenUse == "" {
			t.Errorf("Expected %q header to be set", domain.TOKEN_USE_HEADER)
		}

		if tokenUse != use {
			t.Errorf("Expected token use to be: %q got: %q", use, tokenUse)
		}

		userInfoStr := got.Headers.Get(domain.USER_INFO_HEADER)
		if userInfoStr == "" {
			t.Errorf("Expected %q header to be set", domain.USER_INFO_HEADER)
		}

		userInfoBytes, err := base64.StdEncoding.DecodeString(userInfoStr)

		if err != nil {
			t.Errorf("Expected base64 decode without error, got: %v", err)
		}

		var userInfo domain.User
		err = json.Unmarshal(userInfoBytes, &userInfo)

		if err != nil {
			t.Errorf("Expected json decode without error, got: %v", err)
		}

		if !cmp.Equal(expected, userInfo) {
			t.Errorf("Expected user info to be: %+v got: %+v", expected, userInfo)
		}
	})

	t.Run("Test JWT Refresh Authorization", func(t *testing.T) {
		expected := domain.User{
			Id:       "myId",
			Name:     "Tony Stark",
			Username: "IronMan",
			Picture:  "http://picture.com/ironman",
			Role:     "hero",
			Provider: "StarkIndustries",
			TokenID:  "myTokenID",
		}

		internal := domain.InternalTokenValidator
		use := "refresh"
		route := domain.Route{
			Path:           "my/path",
			Host:           "internal.api",
			Scheme:         "http",
			TokenValidator: &internal,
			TokenUse:       &use,
		}

		externalValidator := mocks.TokenValidator{
			ValidateInterceptor: func(token string) (domain.User, error) {
				t.Errorf("Expected external validator to not be called")
				return expected, nil
			},
			ValidateUseInterceptor: func(token, use string) (domain.User, error) {
				t.Errorf("Expected external validator to not be called")
				return expected, nil
			},
		}

		internalCalled := false
		internalValidator := mocks.TokenValidator{
			ValidateInterceptor: func(token string) (domain.User, error) {
				t.Errorf("Expected internal validator to not be called without use")
				return expected, nil
			},
			ValidateUseInterceptor: func(token string, use string) (domain.User, error) {
				internalCalled = true
				if token != expected.TokenID {
					t.Errorf("Expected validator to be called with token: myToken got: %q", token)
				}

				if use != *route.TokenUse {
					t.Errorf("Expected validator to be called with use: %q got: %q", *route.TokenUse, token)
				}

				return expected, nil
			},
		}

		config := domain.DefaultConfig()
		config.RouteTable["my/path"] = route

		request := domain.Request{
			Scheme: "https",
			Host:   "external.api",
			Path:   "my/path",
			Headers: http.Header{
				"Authorization": []string{fmt.Sprintf("Bearer %s", expected.TokenID)},
			},
		}

		service := NewProxyService(
			&config,
			&mocks.ApiProxy{},
			&externalValidator,
			&internalValidator,
		)
		got, err := service.Authorize(request)

		if err != nil {
			t.Errorf("Expected authorize without error, got: %v", err)
		}

		if !internalCalled {
			t.Errorf("Expected internal validator to be called")
		}

		if got.Path != route.Path {
			t.Errorf("Expected path to be: %q got: %q", route.Path, got.Path)
		}

		if got.Host != route.Host {
			t.Errorf("Expected host to be: %q got: %q", route.Host, got.Host)
		}

		if got.Scheme != route.Scheme {
			t.Errorf("Expected scheme to be: %q got: %q", route.Scheme, got.Scheme)
		}

		requestId := got.Headers.Get(domain.REQUEST_ID_HEADER)
		if requestId == "" {
			t.Errorf("Expected %q header to be set", domain.REQUEST_ID_HEADER)
		}

		tokenUse := got.Headers.Get(domain.TOKEN_USE_HEADER)
		if tokenUse == "" {
			t.Errorf("Expected %q header to be set", domain.TOKEN_USE_HEADER)
		}

		if tokenUse != use {
			t.Errorf("Expected token use to be: %q got: %q", use, tokenUse)
		}

		userInfoStr := got.Headers.Get(domain.USER_INFO_HEADER)
		if userInfoStr == "" {
			t.Errorf("Expected %q header to be set", domain.USER_INFO_HEADER)
		}

		userInfoBytes, err := base64.StdEncoding.DecodeString(userInfoStr)

		if err != nil {
			t.Errorf("Expected base64 decode without error, got: %v", err)
		}

		var userInfo domain.User
		err = json.Unmarshal(userInfoBytes, &userInfo)

		if err != nil {
			t.Errorf("Expected json decode without error, got: %v", err)
		}

		if !cmp.Equal(expected, userInfo) {
			t.Errorf("Expected user info to be: %+v got: %+v", expected, userInfo)
		}
	})
}

func TestRequestValuesArePassed(t *testing.T) {
	route := domain.Route{
		Path:           "my/path",
		Host:           "internal.api",
		Scheme:         "http",
		TokenValidator: nil,
		TokenUse:       nil,
	}
	config := domain.DefaultConfig()
	config.RouteTable["my/path"] = route

	validator := mocks.TokenValidator{
		ValidateInterceptor: func(token string) (domain.User, error) {
			return domain.User{}, errors.New("Validator should not be called")
		},
	}

	t.Run("Test internal headers can't be overridden", func(t *testing.T) {
		headerValue := "MaliciousUseHeader"
		forwardHeader := "X-FORWARDED-FOR"
		request := domain.Request{
			Scheme: "https",
			Host:   "external.api",
			Path:   "my/path",
			Headers: http.Header{
				domain.TOKEN_USE_HEADER:  []string{headerValue},
				domain.USER_INFO_HEADER:  []string{headerValue},
				domain.REQUEST_ID_HEADER: []string{headerValue},
				forwardHeader:            []string{"127.0.0.2"},
			},
		}

		service := NewProxyService(&config, &mocks.ApiProxy{}, &validator, &validator)
		got, err := service.Authorize(request)

		if err != nil {
			t.Errorf("Expected authorize without error, got: %v", err)
		}

		requestId := got.Headers.Get(domain.REQUEST_ID_HEADER)
		if requestId == "" {
			t.Errorf("Expected %q header to be set", domain.REQUEST_ID_HEADER)
		}

		if requestId == headerValue {
			t.Errorf("Expected %q header to not be: %q", domain.REQUEST_ID_HEADER, headerValue)
		}

		tokenUse := got.Headers[domain.TOKEN_USE_HEADER]
		if len(tokenUse) != 0 {
			t.Errorf("Expected %q header to not be set, got: %v", domain.TOKEN_USE_HEADER, tokenUse)
		}

		userInfo := got.Headers[domain.USER_INFO_HEADER]
		if len(userInfo) != 0 {
			t.Errorf("Expected %q header to not be set, got: %v", domain.USER_INFO_HEADER, userInfo)
		}

		forwarded := got.Headers[forwardHeader]
		if len(forwarded) != 1 {
			t.Errorf("Expected %q header to be set, got: %v", forwardHeader, forwarded)
		}

		if forwarded[0] != "127.0.0.2" {
			t.Errorf("Expected %q to be: %q got: %q", forwardHeader, "127.0.0.2", forwarded[0])
		}
	})

	t.Run("Test internal headers can't be overridden", func(t *testing.T) {
		body := "body_contents"
		request := domain.Request{
			Scheme:  "https",
			Host:    "external.api",
			Path:    "my/path",
			Method:  domain.HTTP_GET,
			Query:   "p=1&p=2",
			Body:    io.NopCloser(strings.NewReader(body)),
			Headers: http.Header{},
		}

		service := NewProxyService(&config, &mocks.ApiProxy{}, &validator, &validator)
		got, err := service.Authorize(request)

		if err != nil {
			t.Errorf("Expected authorize without error, got: %v", err)
		}

		if got.Method != request.Method {
			t.Errorf("Expected HTTP method to be: %q, got: %q", request.Method, got.Method)
		}

		buf := new(bytes.Buffer)
		buf.ReadFrom(got.Body)
		gotBody := buf.String()
		if gotBody != body {
			t.Errorf("Expected body to be: %q got: %q", body, gotBody)
		}
	})
}

func TestUnknownRoute(t *testing.T) {
	internal := domain.InternalTokenValidator
	use := "access"
	route := domain.Route{
		Path:           "my/path",
		Host:           "internal.api",
		Scheme:         "http",
		TokenValidator: &internal,
		TokenUse:       &use,
	}

	externalValidator := mocks.TokenValidator{
		ValidateInterceptor: func(token string) (domain.User, error) {
			t.Errorf("Expected external validator to not be called")
			return domain.User{}, nil
		},
		ValidateUseInterceptor: func(token, use string) (domain.User, error) {
			t.Errorf("Expected external validator to not be called")
			return domain.User{}, nil
		},
	}

	internalValidator := mocks.TokenValidator{
		ValidateInterceptor: func(token string) (domain.User, error) {
			t.Errorf("Expected internal validator to not be called")
			return domain.User{}, nil
		},
		ValidateUseInterceptor: func(token string, use string) (domain.User, error) {
			t.Errorf("Expected internal validator to not be called")
			return domain.User{}, nil
		},
	}

	config := domain.DefaultConfig()
	config.RouteTable["my/path"] = route

	request := domain.Request{
		Scheme:  "https",
		Host:    "external.api",
		Path:    "my/other/path",
		Headers: http.Header{},
	}

	service := NewProxyService(
		&config,
		&mocks.ApiProxy{},
		&externalValidator,
		&internalValidator,
	)
	_, err := service.Authorize(request)

	if err != domain.ErrNotFound {
		t.Errorf("Expected error to be: %v got: %v", domain.ErrNotFound, err)
	}
}
