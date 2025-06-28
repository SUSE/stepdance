package web

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	//"net/url"
	"strings"

	"github.com/SUSE/stepdance/cert"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/oauth2-proxy/mockoidc"
	"golang.org/x/oauth2"
)

func realGet(t *testing.T, path string) (*http.Response, string) {
	if path[0:1] == "/" {
		path = "http://localhost:9100" + path
	}

	fmt.Printf("getting %s\n", path)

	r, err := st.c.Get(path)
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("r %+v\n", r)

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		t.Error(err)
	}

	//fmt.Printf("body %s\n", b)

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

func TestMain(m *testing.M) {
	mo, err := mockoidc.Run()
	if err != nil {
		panic(err)
	}
	mcfg := mo.Config()
	defer mo.Shutdown()

	mo.QueueUser(&mockoidc.MockUser{
		Subject: "Testerites",
	})

	st = new(steptest)
	st.s = new(Stepdance)
	st.oidcsrv = mo.Server

	// test/setup.sh
	st.s.Step = cert.NewStep("https://localhost:9000", "9da25f5056fdc3901a827b5e2639af48bef834f17e51a2de15e38e2f775c907e")
	st.s.Ctx = context.Background()

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

	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}

	st.c = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar: jar,
	}

	m.Run()
}

func TestIndex(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	st.srv.Handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("got %d instead of %d", status, http.StatusOK)
	}

	body := rr.Body.String()
	if strings.Contains(body, "Request certificate") {
		t.Error("unexpected return, has \"Request certificate\" button")
	}
	if !strings.Contains(body, "Login") {
		t.Error("unexpected return, misses \"Login\" button")
	}
	if strings.Contains(body, "Hello") {
		t.Error("unexpected return, has logged in greeting")
	}
}

func TestLogin(t *testing.T) {
	// 1. initial request
	r, _ := realGet(t, "/login")

	if status := r.StatusCode; status != http.StatusFound {
		t.Errorf("got %d instead of %d", status, http.StatusFound)
	}

	locationurl, err := r.Location()
	if err != nil {
		t.Error("missing or wrong \"Location\" header")
	}

	location := locationurl.String()

	// TODO: properly parse URL

	// path from mock library
	if !strings.Contains(location, "/oidc/authorize") {
		t.Error("missing or wrong authorization redirection")
	}

	if !strings.Contains(location, "&response_type=code") {
		t.Error("missing or wrong response_type")
	}

	if !strings.Contains(location, "&scope=openid+profile+email") {
		t.Error("missing or wrong scopes")
	}

	// 2. follow the redirect to the OIDC provider
	req := httptest.NewRequest(http.MethodGet, location, nil)
	rr := httptest.NewRecorder()

	st.oidcsrv.Handler.ServeHTTP(rr, req)

	// if this fails, likely a problem with the provider mocking and not with the application
	if status := rr.Code; status != http.StatusFound {
		t.Errorf("got %d instead of %d", status, http.StatusFound)
	}

	headers := rr.HeaderMap

	locations, ok := headers["Location"]
	if !ok || len(locations) != 1 {
		t.Error("missing \"Location\" header or too many of them")
	}

	location = locations[0]

	// TODO: properly parse URL

	if !strings.Contains(location, "/callback") {
		t.Error("missing or wrong callback redirection")
	}

	if !strings.Contains(location, "?code=") || !strings.Contains(location, "&state=") {
		t.Error("wrong parameters in callback redirection")
	}

	// 3. follow the redirect to the service callback
	r, _ = realGet(t, location)

	if status := r.StatusCode; status != http.StatusFound {
		t.Errorf("got %d instead of %d", status, http.StatusFound)
	}

	locationurl, err = r.Location()
	if err != nil {
		t.Error("missing or wrong \"Location\" header")
	}

	location = locationurl.String()

	// 4. follow the redirect to the originally requested path
	r, body := realGet(t, location)

	if status := r.StatusCode; status != http.StatusOK {
		t.Errorf("got %d instead of %d", status, http.StatusOK)
	}

	if strings.Contains(body, "Login") {
		t.Error("unexpected return, has \"Login\" button")
	}
	if !strings.Contains(body, "Hello, Testerites") {
		t.Error("unexpected return, missing greeting")
	}
}
