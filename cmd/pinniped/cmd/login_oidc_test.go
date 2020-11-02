// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/oidcclient"
)

func TestLoginOIDCCommand(t *testing.T) {
	t.Parallel()

	cfgDir := mustGetConfigDir()

	time1 := time.Date(3020, 10, 12, 13, 14, 15, 16, time.UTC)

	tests := []struct {
		name             string
		args             []string
		wantError        bool
		wantStdout       string
		wantStderr       string
		wantIssuer       string
		wantClientID     string
		wantOptionsCount int
	}{
		{
			name: "help flag passed",
			args: []string{"--help"},
			wantStdout: here.Doc(`
				Login using an OpenID Connect provider

				Usage:
				  oidc --issuer ISSUER --client-id CLIENT_ID [flags]

				Flags:
					  --client-id string       OpenID Connect client ID.
				  -h, --help                   help for oidc
					  --issuer string          OpenID Connect issuer URL.
					  --listen-port uint16     TCP port for localhost listener (authorization code flow only).
					  --scopes strings         OIDC scopes to request during login. (default [offline_access,openid,email,profile])
					  --session-cache string   Path to session cache file. (default "` + windowsSafeJoin(cfgDir, "sessions.yaml") + `")
					  --skip-browser           Skip opening the browser (just print the URL).
			`),
		},
		{
			name:      "missing required flags",
			args:      []string{},
			wantError: true,
			wantStdout: here.Doc(`
				Error: required flag(s) "client-id", "issuer" not set
			`),
		},
		{
			name: "success with minimal options",
			args: []string{
				"--client-id", "test-client-id",
				"--issuer", "test-issuer",
			},
			wantIssuer:       "test-issuer",
			wantClientID:     "test-client-id",
			wantOptionsCount: 3,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
		},
		{
			name: "success with all options",
			args: []string{
				"--client-id", "test-client-id",
				"--issuer", "test-issuer",
				"--skip-browser",
				"--listen-port", "1234",
				"--debug-session-cache",
			},
			wantIssuer:       "test-issuer",
			wantClientID:     "test-client-id",
			wantOptionsCount: 5,
			wantStdout:       `{"kind":"ExecCredential","apiVersion":"client.authentication.k8s.io/v1beta1","spec":{},"status":{"expirationTimestamp":"3020-10-12T13:14:15Z","token":"test-id-token"}}` + "\n",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var (
				gotIssuer   string
				gotClientID string
				gotOptions  []oidcclient.Option
			)
			cmd := oidcLoginCommand(func(issuer string, clientID string, opts ...oidcclient.Option) (*oidcclient.Token, error) {
				gotIssuer = issuer
				gotClientID = clientID
				gotOptions = opts
				return &oidcclient.Token{
					IDToken: &oidcclient.IDToken{
						Token:  "test-id-token",
						Expiry: metav1.NewTime(time1),
					},
				}, nil
			})
			require.NotNil(t, cmd)

			var stdout, stderr bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.wantStdout, stdout.String(), "unexpected stdout")
			require.Equal(t, tt.wantStderr, stderr.String(), "unexpected stderr")
			require.Equal(t, tt.wantIssuer, gotIssuer, "unexpected issuer")
			require.Equal(t, tt.wantClientID, gotClientID, "unexpected client ID")
			require.Len(t, gotOptions, tt.wantOptionsCount)
		})
	}
}

// windowsSafeJoin is a function to help us get around a weird double-slash behavior in our help
// test. It should not affect the behavior of a path using '/' separators.
//
// When we create a flag with this help text
//   C:\some\path\to\file.yaml
// then it shows up on the command line as this
//   C:\\some\\path\\to\\file.yaml
// because (I think) the cobra library is doing some backslash escaping.
func windowsSafeJoin(s ...string) string {
	joined := filepath.Join(s...)
	joined = strings.ReplaceAll(joined, `\`, `\\`)
	return joined
}
