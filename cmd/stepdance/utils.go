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
	"log/slog"
	"strconv"
	"time"
)

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
