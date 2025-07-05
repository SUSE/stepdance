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
	"log/slog"
	"os"
)

type logHandler struct {
	*slog.TextHandler
}

func (lh *logHandler) Handle(ctx context.Context, r slog.Record) error {
	if val, ok := ctx.Value("session_id").(string); ok {
		r.AddAttrs(slog.String("session_id", val))
	}

	return lh.TextHandler.Handle(ctx, r)
}

func newLogLevel(inLevel string) slog.Level {
	var outLevel slog.Level
	if err := outLevel.UnmarshalText([]byte(inLevel)); err != nil {
		panic(err)
	}

	return outLevel
}

func newSlog(level slog.Level) *slog.Logger {
	return slog.New(&logHandler{
		TextHandler: slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}),
	})
}
