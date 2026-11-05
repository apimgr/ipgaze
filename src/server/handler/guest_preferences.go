package handler

import (
	"net/http"
	"strings"

	"github.com/apimgr/ipgaze/src/netutil"
)

const (
	lookupWidgetPreferenceCookie = "ipgaze_pref_widget"
	defaultLookupWidget          = "ip"
)

var lookupWidgetPreferences = map[string]struct{}{
	"ip": {}, "country": {}, "country-iso": {}, "city": {}, "asn": {}, "json": {}, "port": {},
}

func validLookupWidget(value string) bool {
	_, ok := lookupWidgetPreferences[value]
	return ok
}

func lookupWidgetPreference(r *http.Request) string {
	if cookie, err := r.Cookie(lookupWidgetPreferenceCookie); err == nil && validLookupWidget(cookie.Value) {
		return cookie.Value
	}
	return defaultLookupWidget
}

func setLookupWidgetPreference(w http.ResponseWriter, r *http.Request, trust *netutil.TrustResolver, value string) {
	if !validLookupWidget(value) {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     lookupWidgetPreferenceCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60,
		SameSite: http.SameSiteLaxMode,
		Secure:   isSecurePreferenceRequest(r, trust),
	})
}

func isSecurePreferenceRequest(r *http.Request, trust *netutil.TrustResolver) bool {
	return strings.HasPrefix(netutil.BuildURL(r, trust, "/"), "https://")
}
