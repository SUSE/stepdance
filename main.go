package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/smallstep/certificates/ca"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func main() {
	var (
		configArg   string
		logLevelArg string
	)
	// ugly flagset approach because smallstep/certificates/ca pulls in golang/glog which mangles global flags
	fs := flag.NewFlagSet("stepdance", flag.ExitOnError)
	fs.StringVar(&configArg, "config", "./config.json", "Configuration file")
	fs.StringVar(&logLevelArg, "loglevel", "info", "Logging level")
	fs.Parse(os.Args[1:])

	var logLevel slog.Level
	if err := logLevel.UnmarshalText([]byte(logLevelArg)); err != nil {
		panic(err)
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

	c := newConfig(configArg)

	slog.Info("Booting Stepdance ...")

	slog.Debug("Initializing CA client ...")

	client, err := ca.NewClient(c.CaUrl, ca.WithRootSHA256(c.CaHash))
	if err != nil {
		slog.Error("Could not initiate CA client", "error", err)
		os.Exit(1)
	}

	health, err := client.Health()
	if err != nil {
		slog.Error("CA is not healthy", "error", err)
		os.Exit(1)
	}

	slog.Debug("Got CA health response", "status", health.Status)

	s := new(Stepdance)

	s.ctx = context.Background()
	s.step = client

	slog.Debug("Initializing OIDC provider ...")

	provider, err := oidc.NewProvider(s.ctx, c.OidcBaseUrl)
	if err != nil {
		panic(err)
	}

	s.oidcConfig = &oidc.Config{
		ClientID: c.ClientId,
	}

	s.oidcProvider = provider

	s.verifier = provider.Verifier(s.oidcConfig)

	// todo: IPv6 wrap
	bind := fmt.Sprintf("%s:%d", c.BindAddress, c.BindPort)

	slog.Debug("Initializing Oauth2 ...")

	s.oauth2Config = oauth2.Config{
		ClientID:     c.ClientId,
		ClientSecret: c.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://" + bind + "/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	slog.Debug("Initialization sequence complete, starting web server ...")

	initStepdance(s, bind)
}
