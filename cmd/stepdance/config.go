package main

import (
	"encoding/json"
	"log/slog"
	"os"
)

type topConfig struct {
	Config Config `json:"config"`
}

type Config struct {
	BindAddress  string
	BindPort     int
	CaUrl        string
	CaDbUrl      string
	CaDbRefresh  string
	CaPass       string
	CaHash       string
	ClientId     string
	ClientSecret string
	OidcBaseUrl  string
}

func newConfig(file string) Config {
	c := new(topConfig)

	fh, err := os.Open(file)
	if err != nil {
		slog.Error("Failed to open configuration file", "error", err)
		os.Exit(1)
	}
	defer fh.Close()

	json.NewDecoder(fh).Decode(&c)

	return c.Config
}
