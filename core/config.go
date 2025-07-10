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

package core

import (
	"encoding/json"
	"log/slog"
	"os"
	"strconv"
	"time"
)

type topConfig struct {
	Config Config `json:"config"`
}

type Config struct {
	AppBaseUrl   string
	BindAddress  string
	BindPort     int
	CaAdminProv  string
	CaCert       string
	CaUrl        string
	CaDbUrl      string
	CaDbRefresh  string
	CaPass       string
	CaHash       string
	ClientId     string
	ClientSecret string
	OidcBaseUrl  string
}

func NewConfig(file string) Config {
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

func GetInterval(input string) *time.Duration {
	if input == "" {
		tdtmp := (5 * time.Minute)
		return &tdtmp
	} else {
		return parseConfigTime(input)
	}
}

func parseConfigTime(input string) *time.Duration {
	if input == "" {
		return nil
	}

	var timeUnit time.Duration

	unit := input[len(input)-1:]
	switch unit {
	case "m":
		timeUnit = time.Minute
	case "s":
		timeUnit = time.Second
	default:
		slog.Error("Invalid time unit in CaDbRefresh", "value", input, "unit", unit)
		return nil
	}

	value, err := strconv.Atoi(input[:len(input)-1])
	if err != nil {
		slog.Error("Invalid time value in CaDbRefresh", "value", input, "error", err)
		return nil
	}

	td := (time.Duration(value) * timeUnit)

	return &td
}
