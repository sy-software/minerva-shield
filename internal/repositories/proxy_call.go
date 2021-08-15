package repositories

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/sy-software/minerva-shield/internal/core/domain"
)

type ProxyCaller struct {
	config *domain.Config
}

func NewProxyCaller(config *domain.Config) *ProxyCaller {
	return &ProxyCaller{
		config: config,
	}
}

func (caller *ProxyCaller) Call(request domain.Request) (domain.Proxy, error) {
	remote, err := url.Parse(fmt.Sprintf("%s://%s", request.Scheme, request.Host))

	if err != nil {
		return nil, errors.New("can't connect to remote")
	}

	proxy := httputil.NewSingleHostReverseProxy(remote)

	proxy.Director = func(req *http.Request) {
		// TODO: Log requests
		// b, _ := ioutil.ReadAll(req.Body)
		// fmt.Println(string(b))
		req.Header = request.Headers
		req.Host = request.Host
		req.URL.Scheme = request.Scheme
		req.URL.Host = request.Host
		req.URL.Path = request.Path
		req.URL.RawQuery = request.Query
		req.Body = request.Body
	}

	return proxy, nil
}
