/*
   Stepdance - a client certificate management portal
   Copyright (C) 2025  SUSE LLC <georg.pfuetzenreuter@suse.com>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package web

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	//"net/url"
	"os/exec"
	"strings"

	"github.com/SUSE/stepdance/cert"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

const (
	srvapp  = 0
	srvoidc = 1
)

// performs a GET request against the live server as opposed to mocking a handler
// returns the response object and the decoded body
func realGet(t *testing.T, path string) (*http.Response, string) {
	t.Helper()

	if path[0:1] == "/" {
		path = "http://localhost:9100" + path
	}

	fmt.Printf("getting %s\n", path)

	r, err := st.c.Get(path)
	if err != nil {
		t.Error(err)
	}

	//fmt.Printf("r %+v\n", r)

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		t.Error(err)
	}

	// for debugging the cookie jar
	/*
	for _, cookie := range r.Cookies() {
		fmt.Printf("cookie in res: %s => %s on %s\n", cookie.Name, cookie.Value, cookie.Domain)
	}

	for _, cookie := range st.c.Jar.Cookies(&url.URL{Scheme: "http", Host: "localhost"}) {
		fmt.Printf("cookie in jar: %s: %s\n", cookie.Name, cookie.Value)
	}
	*/

	return r, string(b)
}

// performs a GET request against a mocked handler
// returns the response object and body
func mockGet(t *testing.T, path string, srv int) (*httptest.ResponseRecorder, string) {
	t.Helper()

	r := httptest.NewRequest(http.MethodGet, path, nil)
	rr := httptest.NewRecorder()

	switch srv {
	case srvapp:
		st.srv.Handler.ServeHTTP(rr, r)
	case srvoidc:
		st.oidcsrv.Handler.ServeHTTP(rr, r)
	}

	return rr, rr.Body.String()
}

// test for expected response code with common message
func assertStatusEqual(t *testing.T, have int, want int) {
	t.Helper()

	assert.Equalf(t, want, have, "Have status %d, but want status %d", have, want)
}

// test and return "Location" value after realGet()
func realLocation(t *testing.T, r *http.Response) string {
	t.Helper()

	location, err := r.Location()
	if err != nil {
		t.Error("missing or wrong \"Location\" header")
	}

	return location.String()
}

// setup/teardown
func TestMain(m *testing.M) {
	// perpare mocked OIDC provider
	// (manually instead of .Run() due to need for static port)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	mo, err := mockoidc.NewServer(rsaKey)
	if err != nil {
		panic(err)
	}
	ln, err := net.Listen("tcp", "localhost:9200")
	if err != nil {
		panic(err)
	}
	mo.Start(ln, nil)
	//mo, err := mockoidc.Run()
	if err != nil {
		panic(err)
	}
	mcfg := mo.Config()
	defer mo.Shutdown()

	// define a user which will log in
	// (the default mockoidc user would suffice, but we set a subject name which is easier to search for)
	mo.QueueUser(&mockoidc.MockUser{
		Subject: "Testerites",
	})

	st = new(steptest)
	st.s = new(Stepdance)
	st.oidcsrv = mo.Server

	// connect to StepCA as deployed by test/setup.sh
	st.s.Step = cert.NewStep(
		"https://localhost:9000",
		"9da25f5056fdc3901a827b5e2639af48bef834f17e51a2de15e38e2f775c907e",
		"postgresql://step:step@localhost/step",
		"ThisIsDumb",
	)
	st.s.Ctx = context.Background()

	// regular stepdance initialization below
	// should align with cmd/stepdance/main.go (TODO: move this to some common function)

	provider, err := oidc.NewProvider(st.s.Ctx, mo.Issuer())
	if err != nil {
		panic(err)
	}

	st.s.OidcConfig = &oidc.Config{
		ClientID: mcfg.ClientID,
	}

	st.s.OidcProvider = provider
	st.s.Verifier = provider.Verifier(st.s.OidcConfig)

	st.s.Oauth2Config = oauth2.Config{
		ClientID:     mcfg.ClientID,
		ClientSecret: mcfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://localhost:9100/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	st.srv = InitStepdance(st.s, "[::1]:9100")
	defer st.srv.Shutdown(context.Background())

	// very ugly, refactor to Go code would be nice but then again this works for the test purposes ...
	cmd := exec.Command("podman", "exec", "t-stepdance-stepca", "step", "ca", "provisioner", "list")
	output, err := cmd.CombinedOutput()
	outstr := string(output)
	if err != nil {
		fmt.Printf("command: %s\noutput: %s", cmd.String(), outstr)
		panic(err)
	}
	if strings.Contains(outstr, "OIDC") {
		cmd := exec.Command("podman", "exec", "t-stepdance-stepca", "step", "ca", "provisioner", "remove", "OIDC", "--admin-provisioner=Admin JWK", "--admin-name=step", "--admin-password-file=provisioner_password")
		output, err := cmd.CombinedOutput()
		fmt.Printf("command: %s\noutput: %s", cmd.String(), output)
		if err != nil {
			panic(err)
		}
	}
	cmd = exec.Command("podman", "exec", "t-stepdance-stepca", "step", "ca", "provisioner", "add", "OIDC", "--type=oidc", "--client-id="+mcfg.ClientID, "--client-secret="+mcfg.ClientSecret, "--configuration-endpoint="+mo.DiscoveryEndpoint(), "--domain=localhost", "--ssh=false", "--disable-smallstep-extensions", "--admin-provisioner=Admin JWK", "--admin-name=step", "--admin-password-file=provisioner_password")
	output, err = cmd.CombinedOutput()
	fmt.Printf("command: %s\noutput: %s", cmd.String(), output)
	if err != nil {
		panic(err)
	}

	// prepare cookie jar for persistence of session cookie in authenticated tests
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}

	st.c = &http.Client{
		// block automated redirects as we want to evaluate the response before requesting the next location
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar: jar,
	}

	m.Run()
}

func TestIndexAnonymous(t *testing.T) {
	r, body := mockGet(t, "/", srvapp)

	assertStatusEqual(t, r.Code, http.StatusOK)
	// there is assert.HTTPBodyContains, but it does not fit as it expects individual handlers, whereas we test the server as a whole
	assert.NotContains(t, body, "Request certificate", "unexpected return, has \"Request certificate\" button")
	assert.Contains(t, body, "Login", "unexpected return, misses \"Login\" button")
	assert.NotContains(t, body, "Hello", "unexpected return, has logged in greeting")
}

func TestLogin(t *testing.T) {
	// 1. initial request
	r, _ := realGet(t, "/login/init")

	assertStatusEqual(t, r.StatusCode, http.StatusFound)

	location := realLocation(t, r)

	// TODO: properly parse URLs instead of Contains

	// path from mock library
	assert.Contains(t, location, "/oidc/authorize", "missing or wrong authorization redirection")

	assert.Contains(t, location, "&response_type=code", "missing or wrong response_type")
	assert.Contains(t, location, "&scope=openid+profile+email", "missing or wrong scopes")

	// 2. follow the redirect to the OIDC provider
	rr, _ := mockGet(t, location, srvoidc)

	// if this fails it is likely a problem with the provider mocking and not with our application
	assertStatusEqual(t, rr.Code, http.StatusFound)

	headers := rr.HeaderMap
	locations, ok := headers["Location"]
	if !ok || len(locations) != 1 {
		t.Error("missing \"Location\" header or too many of them")
	}
	location = locations[0]

	assert.Contains(t, location, "/callback", "missing or wrong callback redirection")
	assert.Contains(t, location, "?code=", "missing or wrong \"code\" parameter in callback redirection")
	assert.Contains(t, location, "&state=", "missing or wrong \"state\" callback redirection")

	// 3. follow the redirect to the service callback
	r, _ = realGet(t, location)

	assertStatusEqual(t, r.StatusCode, http.StatusFound)

	location = realLocation(t, r)

	// 4. follow the redirect to the originally requested path
	r, _ = realGet(t, location)

	assertStatusEqual(t, r.StatusCode, http.StatusOK)
}

func TestIndexAuthenticatedWithoutCerts(t *testing.T) {
	r, body := realGet(t, "/")

	assertStatusEqual(t, r.StatusCode, http.StatusOK)

	assert.NotContains(t, body, "Login", "unexpected return, has \"Login\" button")
	assert.Contains(t, body, "Hello, Testerites", "unexpected return, missing greeting")
	assert.NotContains(t, body, "<table class=\"overview\">", "unexpected return, certificate table without certificates")
	assert.Contains(t, body, "Request certificate", "unexpected return, missing \"Request certificate\" button")
}

func TestRequestCert(t *testing.T) {
	r, body := realGet(t, "/certificate/request")

	assertStatusEqual(t, r.StatusCode, http.StatusOK)

	assert.Contains(t, body, "Download certificate", "missing \"Download certificate\" button")
	assert.Contains(t, body, "Download private key", "missing \"Download private key\" button")
}

func TestIndexAuthenticatedWithCerts(t *testing.T) {
	r, body := realGet(t, "/")

	assertStatusEqual(t, r.StatusCode, http.StatusOK)

	assert.NotContains(t, body, "Login", "unexpected return, has \"Login\" button")
	assert.Contains(t, body, "Hello, Testerites", "unexpected return, missing greeting")
	assert.Contains(t, body, "<table class=\"overview\">", "unexpected return, missing certificate table")
	assert.Contains(t, body, "Request certificate", "unexpected return, missing \"Request certificate\" button")
}
