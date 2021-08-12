package service

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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

	service := NewProxyService(&config, &validator, &validator)
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
		&externalValidator,
		&internalValidator,
	)
	_, err := service.Authorize(request)

	if err != ErrNotFound {
		t.Errorf("Expected error to be: %v got: %v", ErrNotFound, err)
	}
}
