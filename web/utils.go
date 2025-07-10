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

package web

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
)

const pkgWebDir = "/usr/share/stepdance/web"

func getWebDir(purpose string) string {
	var webdir string

	if purpose != "static" && purpose != "templates" {
		slog.Error("invalid use of getWebDir()")
		os.Exit(1)
	}

	wd := os.Getenv("STEPDANCE_WEBDIR")
	shared, err := os.Stat(pkgWebDir)

	if err != nil {
		slog.Debug("Failed to open shared web directory", "purpose", purpose, "error", err)
	}

	if st != nil {
		webdir = "./"
	} else if wd != "" {
		webdir = wd
	} else if err == nil && shared.IsDir() {
		webdir = pkgWebDir
	} else {
		wd, _ = os.Getwd()
		webdir = wd + "/web"
	}

	if webdir[len(webdir)-1:] != "/" {
		webdir = webdir + "/"
	}

	webdir = webdir + purpose + "/"

	slog.Debug("Got web directory", "purpose", purpose, "path", webdir)

	return webdir
}

func randString(nByte int, urlEncode bool) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	if urlEncode {
		return base64.RawURLEncoding.EncodeToString(b), nil
	}

	return hex.EncodeToString(b), nil
}
