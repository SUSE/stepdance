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
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/SUSE/stepdance/core"
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

	slog.SetDefault(newSlog(newLogLevel(logLevelArg)))

	c := core.NewConfig(configArg)

	slog.Info("Booting Stepdance ...")

	s, bind := web.NewStepdance(c)

	td := core.GetInterval(c.CaDbRefresh)
	if td == nil {
		os.Exit(1)
	}

	slog.Debug("Initialization sequence complete, starting web server and scheduler ...")

	cs := make(chan os.Signal, 1)
	signal.Notify(cs, os.Interrupt)

	srv := web.InitStepdance(s, bind)
	defer srv.Shutdown(context.Background())

	tt := time.Tick(*td)

main:
	for {
		select {
		case <-cs:
			slog.Debug("Received interrupt")
			break main
		case <-tt:
			slog.Debug("Tick")
			if c.CaDbUrl != "" {
				s.Step.RefreshCertificates()
			}
		}
	}

	slog.Info("Shutting down ...")
}
