package cert

import (
	"github.com/smallstep/certificates/ca"
	"log/slog"
	"os"
)

type Step struct {
	client *ca.Client
}

func NewStep(url string, hash string) *Step {
	s := new(Step)

	slog.Debug("Initializing CA client ...")

	client, err := ca.NewClient(url, ca.WithRootSHA256(hash))
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

	s.client = client

	return s
}
