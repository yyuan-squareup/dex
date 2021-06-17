// Package authproxy implements a connector which relies on external
// authentication (e.g. mod_auth in Apache2) and returns an identity with the
// HTTP header X-Remote-User as verified email.
package authproxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
)

// Config holds the configuration parameters for a connector which returns an
// identity with the HTTP header X-Remote-User as verified email.
type Config struct {
	// the header whose value is the user's email
	UserHeader string `json:"userHeader"`
	// an optional base path to an endpoint where Dex can find Group claims for the user.
	// the username will be appended to the end of the base path with leading `/` if none exists
	// ie. a basepath of "localhost/api/roles" becomes "localhost/api/roles/johndoe"
	UserGroupsBasePath string `json:"userGroupsBasePath"`
	// an optional callback url override
	CallbackURL string `json:"callbackURL"`
}

// Open returns an authentication strategy which requires no user interaction.
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	userHeader := c.UserHeader
	if userHeader == "" {
		userHeader = "X-Remote-User"
	}

	return &callback{
		userHeader:         userHeader,
		userGroupsBasePath: c.UserGroupsBasePath,
		callbackURL:        c.CallbackURL,
		logger:             logger,
		pathSuffix:         "/" + id,
	}, nil
}

// Callback is a connector which returns an identity with the HTTP header
// X-Remote-User as verified email.
type callback struct {
	userHeader         string
	userGroupsBasePath string
	callbackURL        string
	logger             log.Logger
	pathSuffix         string
}

// LoginURL returns the URL to redirect the user to login with.
func (m *callback) LoginURL(s connector.Scopes, callbackURL, state string) (string, error) {
	if m.callbackURL != "" {
		callbackURL = m.callbackURL
	}
	u, err := url.Parse(callbackURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse callbackURL %q: %v", callbackURL, err)
	}
	u.Path += m.pathSuffix
	v := u.Query()
	v.Set("state", state)
	u.RawQuery = v.Encode()
	return u.String(), nil
}

// HandleCallback parses the request and returns the user's identity
func (m *callback) HandleCallback(s connector.Scopes, r *http.Request) (connector.Identity, error) {
	remoteUser := r.Header.Get(m.userHeader)
	if remoteUser == "" {
		return connector.Identity{}, fmt.Errorf("required HTTP header %s is not set", m.userHeader)
	}

	var groups []string

	if m.userGroupsBasePath != "" {
		u, err := url.Parse(m.userGroupsBasePath)
		if err != nil {
			return connector.Identity{}, fmt.Errorf("parsing group claims endpoint [%s] failed: %s", m.userGroupsBasePath, err)
		}

		u.Path = path.Join(u.Path, remoteUser)
		resp, err := http.Get(u.String())
		if err != nil {
			return connector.Identity{}, fmt.Errorf("request to group claims endpoint [%s] failed: %s", m.userGroupsBasePath, err)
		}

		var groupResponse struct {
			Groups []string `json:"groups"`
		}

		err = json.NewDecoder(resp.Body).Decode(&groupResponse)
		if err != nil {
			return connector.Identity{}, fmt.Errorf("request to group claims endpoint %s failed: %s", m.userGroupsBasePath, err)
		}
		groups = groupResponse.Groups
	}

	// TODO: add support for X-Remote-Group, see
	// https://kubernetes.io/docs/admin/authentication/#authenticating-proxy
	return connector.Identity{
		UserID:        remoteUser, // TODO: figure out if this is a bad ID value.
		Email:         remoteUser,
		EmailVerified: true,
		Groups:        groups,
	}, nil
}
