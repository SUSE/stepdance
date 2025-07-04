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
	AppBaseUrl   string
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

	if err := json.NewDecoder(fh).Decode(&c); err != nil {
		slog.Error("Failed to parse configuration file", "error", err)
		os.Exit(1)
	}

	return c.Config
}
