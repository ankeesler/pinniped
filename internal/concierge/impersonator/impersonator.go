// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package impersonator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/go-logr/logr"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/bearertoken"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"

	"go.pinniped.dev/generated/1.20/apis/concierge/login"
	loginv1alpha1 "go.pinniped.dev/generated/1.20/apis/concierge/login/v1alpha1"
	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
)

// allowedHeaders are the set of HTTP headers that are allowed to be forwarded through the impersonation proxy.
//nolint: gochecknoglobals
var allowedHeaders = []string{
	"Accept",
	"Accept-Encoding",
	"User-Agent",
	"Connection",
	"Upgrade",
}

type Proxy struct {
	cache *authncache.Cache
	proxy *httputil.ReverseProxy
	log   logr.Logger
}

func New(cache *authncache.Cache, log logr.Logger) (*Proxy, error) {
	return newInternal(cache, log, rest.InClusterConfig)
}

func newInternal(cache *authncache.Cache, log logr.Logger, getConfig func() (*rest.Config, error)) (*Proxy, error) {
	kubeconfig, err := getConfig()
	if err != nil {
		return nil, fmt.Errorf("could not get in-cluster config: %w", err)
	}

	serverURL, err := url.Parse(kubeconfig.Host)
	if err != nil {
		return nil, fmt.Errorf("could not parse host URL from in-cluster config: %w", err)
	}

	kubeTransportConfig, err := kubeconfig.TransportConfig()
	if err != nil {
		return nil, fmt.Errorf("could not get in-cluster transport config: %w", err)
	}
	kubeTransportConfig.TLS.NextProtos = []string{"http/1.1"}

	kubeRoundTripper, err := transport.New(kubeTransportConfig)
	if err != nil {
		return nil, fmt.Errorf("could not get in-cluster transport: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(serverURL)
	proxy.Transport = kubeRoundTripper

	return &Proxy{
		cache: cache,
		proxy: proxy,
		log:   log,
	}, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := p.log.WithValues(
		"url", r.URL.String(),
		"method", r.Method,
	)

	// Never mutate request (see http.Handler docs).
	//
	// Note that call bearertoken.Authenticator will delete the Authorization header for safety, so we
	// need to clone the http.Request here.
	r = r.Clone(r.Context())

	userInfo, httpErr := authenticate(r, p.cache, &log)
	if httpErr != nil {
		http.Error(w, httpErr.message, httpErr.code)
		return
	}
	if userInfo == nil {
		log.Info("received token that did not authenticate")
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}
	log = log.WithValues("userID", userInfo.GetUID())

	r.Header = getProxyHeaders(userInfo, r.Header)

	log.Info("proxying authenticated request")
	p.proxy.ServeHTTP(w, r)
}

type httpErr struct {
	message string
	code    int
}

func (h *httpErr) Error() string {
	return h.message
}

type authenticateTokenFunc func(ctx context.Context, token string) (*authenticator.Response, bool, error)

func (f authenticateTokenFunc) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	return f(ctx, token)
}

func authenticate(r *http.Request, cache *authncache.Cache, log *logr.Logger) (user.Info, *httpErr) {
	a := bearertoken.New(authenticateTokenFunc(func(ctx context.Context, token string) (*authenticator.Response, bool, error) {
		tokenCredentialReq, err := extractToken(token)
		if err != nil {
			(*log).Error(err, "invalid token encoding")
			return nil, false, &httpErr{message: "invalid token encoding", code: http.StatusBadRequest}
		}
		*log = (*log).WithValues(
			"authenticator", tokenCredentialReq.Spec.Authenticator,
			"authenticatorNamespace", tokenCredentialReq.Namespace,
		)

		userInfo, err := cache.AuthenticateTokenCredentialRequest(r.Context(), tokenCredentialReq)
		if err != nil {
			(*log).Error(err, "received invalid token")
			return nil, false, &httpErr{message: "invalid token", code: http.StatusUnauthorized}
		}

		return &authenticator.Response{User: userInfo}, true, nil
	}))
	resp, authenticated, err := a.AuthenticateRequest(r)
	if err != nil {
		if httpErr, ok := err.(*httpErr); ok {
			return nil, httpErr
		}
		return nil, &httpErr{message: "unexpected error", code: http.StatusInternalServerError}
	}
	if !authenticated {
		err := &httpErr{message: "invalid token encoding", code: http.StatusBadRequest}
		(*log).Error(constable.Error("missing bearer token"), err.message)
		return nil, err
	}
	return resp.User, nil
}

func getProxyHeaders(userInfo user.Info, requestHeaders http.Header) http.Header {
	newHeaders := http.Header{}
	newHeaders.Set("Impersonate-User", userInfo.GetName())
	for _, group := range userInfo.GetGroups() {
		newHeaders.Add("Impersonate-Group", group)
	}
	for _, header := range allowedHeaders {
		values := requestHeaders.Values(header)
		for i := range values {
			newHeaders.Add(header, values[i])
		}
	}
	return newHeaders
}

func extractToken(encoded string) (*login.TokenCredentialRequest, error) {
	tokenCredentialRequestJSON, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in encoded bearer token: %w", err)
	}

	var v1alpha1Req loginv1alpha1.TokenCredentialRequest
	if err := json.Unmarshal(tokenCredentialRequestJSON, &v1alpha1Req); err != nil {
		return nil, fmt.Errorf("invalid TokenCredentialRequest encoded in bearer token: %w", err)
	}
	var internalReq login.TokenCredentialRequest
	if err := loginv1alpha1.Convert_v1alpha1_TokenCredentialRequest_To_login_TokenCredentialRequest(&v1alpha1Req, &internalReq, nil); err != nil {
		return nil, fmt.Errorf("failed to convert v1alpha1 TokenCredentialRequest to internal version: %w", err)
	}
	return &internalReq, nil
}
