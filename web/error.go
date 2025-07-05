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
	"net/http"
)

const (
	SD_ERR_MISC  = 0 // internal issue
	SD_ERR_CODE  = 1 // no or unexpected code value in session
	SD_ERR_STATE = 2 // no or unexpected state value in session
	SD_ERR_TOKEN = 3 // no or unexpected token value in session
	SD_ERR_PARAM = 4 // missing query parameters
	SD_ERR_ILLEG = 5 // operation on data not owned by requestor
)

func (s *Stepdance) errorHandler(w http.ResponseWriter, r *http.Request, sdErr int, text string) {
	p := newErrorData(text, s.getSessionId(r))

	switch sdErr {
	case SD_ERR_MISC:
		w.WriteHeader(http.StatusInternalServerError)
		s.templates.InternalError.ExecuteTemplate(w, "base", p)
	case SD_ERR_CODE:
		w.WriteHeader(http.StatusBadRequest)
		s.templates.MissingCode.ExecuteTemplate(w, "base", p)
	case SD_ERR_PARAM:
		w.WriteHeader(http.StatusBadRequest)
		s.templates.MissingParameter.ExecuteTemplate(w, "base", p)
	case SD_ERR_STATE:
		w.WriteHeader(http.StatusBadRequest)
		s.templates.BadState.ExecuteTemplate(w, "base", p)
	case SD_ERR_TOKEN:
		w.WriteHeader(http.StatusBadRequest)
		s.templates.MissingToken.ExecuteTemplate(w, "base", p)
	case SD_ERR_ILLEG:
		w.WriteHeader(http.StatusForbidden)
		s.templates.Illegal.ExecuteTemplate(w, "base", p)
	}
}
