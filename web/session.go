package web

import (
	"github.com/alexedwards/scs/v2"
	"time"
)

func newSessionManager() *scs.SessionManager {
	sm := scs.New()
	sm.Lifetime = 60 * time.Second
	if st == nil {
		sm.Cookie.Secure = true
	}
	sm.Cookie.HttpOnly = true
	//sm.sessionManager.Cookie.SameSite = http.SameSiteStrictMode

	return sm
}
