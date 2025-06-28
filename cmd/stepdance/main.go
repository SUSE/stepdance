package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"

	"github.com/SUSE/stepdance/cert"
	"github.com/SUSE/stepdance/web"
)

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

	s := new(web.Stepdance)

	s.Step = cert.NewStep(c.CaUrl, c.CaHash)

	s.Ctx = context.Background()

	slog.Debug("Initializing OIDC provider ...")

	provider, err := oidc.NewProvider(s.Ctx, c.OidcBaseUrl)
	if err != nil {
		panic(err)
	}

	s.OidcConfig = &oidc.Config{
		ClientID: c.ClientId,
	}

	s.OidcProvider = provider

	s.Verifier = provider.Verifier(s.OidcConfig)

	// todo: IPv6 wrap
	bind := fmt.Sprintf("%s:%d", c.BindAddress, c.BindPort)

	slog.Debug("Initializing Oauth2 ...")

	s.Oauth2Config = oauth2.Config{
		ClientID:     c.ClientId,
		ClientSecret: c.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://" + bind + "/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	slog.Debug("Initialization sequence complete, starting web server ...")

	cs := make(chan os.Signal, 1)

	srv := web.InitStepdance(s, bind)
	defer srv.Shutdown(context.Background())

	signal.Notify(cs, os.Interrupt)

	<-cs
}
