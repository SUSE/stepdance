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

package cert

import (
	"database/sql"
	"log/slog"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func NewDb(url string) *sql.DB {
	slog.Debug("Initializing CA database client ...")

	db, err := sql.Open("pgx", url)
	if err != nil {
		slog.Error("Could not initiate CA database client", "error", err)
		os.Exit(1)
	}

	err = db.Ping()
	if err != nil {
		slog.Error("Failed to ping CA database", "error", err)
		os.Exit(1)
	}

	return db
}
