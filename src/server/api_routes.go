package server

import (
	"net/http"
	"strings"

	"github.com/apimgr/ipgaze/src/common/i18n"
	"github.com/apimgr/ipgaze/src/server/handler"
	"github.com/apimgr/ipgaze/src/swagger"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// apiRoutes returns the canonical versioned API route values with their live
// handlers attached. Router, docs and discovery consume the same values.
func (s *Server) apiRoutes(versionHandler http.Handler, mcpHandler http.Handler) []swagger.Route {
	staticHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("v") == s.AssetStamp() {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("ETag", `"`+s.AssetStamp()+`"`)
		}
		http.StripPrefix("/static/", StaticHandler()).ServeHTTP(w, r)
	})
	cliBinaryHandler := http.Handler(s.cliBinaryDownloadHandler())
	if s.config != nil && s.config.Server.CLI.BinaryDownload.RequireAuth {
		cliBinaryHandler = s.RequireOperatorToken(cliBinaryHandler)
	}
	linkedTokenPageAction := func(action string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			publicID := chi.URLParam(r, "id")
			if _, err := uuid.Parse(publicID); err != nil {
				http.Redirect(w, r, "/server/preferences/tokens", http.StatusSeeOther)
				return
			}
			s.PagesHandler.ServerPreferencesLinkedTokenActionHandler(w, r, publicID, action)
		}
	}
	handlers := swagger.APIHandlers{
		Static:           staticHandler,
		ThemeCSS:         s.themeCSSHandler(),
		BrandingLogo:     s.brandingLogoHandler(),
		CLIBinary:        cliBinaryHandler.ServeHTTP,
		Robots:           s.SpecialHandler.RobotsTxtHandler,
		Sitemap:          s.sitemapHandler(),
		AtomFeed:         s.feedHandler(true),
		RSSFeed:          s.feedHandler(false),
		Favicon:          s.faviconHandler(),
		SecurityTxt:      s.SpecialHandler.SecurityTxtHandler,
		PGPKey:           s.SpecialHandler.PGPKeyHandler,
		LLMsTxt:          s.SpecialHandler.LLMsTxtHandler,
		WellKnownLLMsTxt: s.SpecialHandler.LLMsTxtHandler,
		Manifest:         s.SpecialHandler.ManifestHandler,
		ServiceWorker:    s.SpecialHandler.ServiceWorkerHandler,
		Locales: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			lang := chi.URLParam(r, "lang")
			data, err := i18n.LocaleJSON(lang)
			if err != nil {
				detectedLang := i18n.DetectLocale(r)
				writeNegotiatedError(w, r, http.StatusNotFound, "", i18n.T(i18n.WithLang(r.Context(), detectedLang), "errors.not_found"))
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=86400")
			w.Write(data) //nolint:errcheck
		}).ServeHTTP,
		Root:           s.rootHandler(),
		JSONRoot:       appHandlerToHTTP(s.JSONHandler),
		IPRoot:         appHandlerToHTTP(s.CLIHandler),
		IPTxtRoot:      appHandlerToHTTP(s.CLIHandler),
		IPLookupRoot:   s.ipLookupOrNotFound(),
		Info:           appHandlerToHTTP(s.APIV1InfoHandler),
		JSON:           appHandlerToHTTP(s.APIV1InfoHandler),
		IP:             appHandlerToHTTP(s.APIV1IPHandler),
		IPLookup:       appHandlerToHTTP(s.APIV1IPLookupHandler),
		Health:         s.HealthHandler.APIV1HealthzHandler,
		HealthText:     s.HealthHandler.APIV1HealthzHandler,
		Version:        versionHandler.ServeHTTP,
		About:          s.PagesHandler.APIV1ServerAboutHandler,
		Help:           s.PagesHandler.APIV1ServerHelpHandler,
		HelpMCP:        s.PagesHandler.APIV1ServerMCPHelpHandler,
		Privacy:        s.PagesHandler.APIV1ServerPrivacyHandler,
		DPO:            s.PagesHandler.APIV1ServerDPOHandler,
		Terms:          s.PagesHandler.APIV1ServerTermsHandler,
		Security:       s.PagesHandler.APIV1ServerSecurityHandler,
		SecurityPolicy: s.PagesHandler.APIV1ServerSecurityPolicyHandler,
		SecurityThanks: s.PagesHandler.APIV1ServerSecurityThanksHandler,
		ContactGet:     s.PagesHandler.APIV1ServerContactHandler,
		ContactPost:    s.PagesHandler.APIV1ServerContactHandler,
		AuthCheck: s.RequireOperatorToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handler.SendAPIResponseOK(w, struct {
				Kind string `json:"kind"`
			}{Kind: "operator"}, nil)
		})).ServeHTTP,
		Preferences:           s.PagesHandler.APIV1ServerPreferencesHandler,
		PreferencesUpdate:     s.PagesHandler.APIV1ServerPreferencesUpdateHandler,
		PreferencesSync:       s.PagesHandler.APIV1ServerPreferencesSyncHandler,
		PreferencesSyncImport: s.PagesHandler.APIV1ServerPreferencesSyncImportHandler,
		TokensList:            s.PagesHandler.APIV1ServerTokensListHandler,
		TokensIssue:           s.PagesHandler.APIV1ServerTokensIssueHandler,
		TokensPrimaryReveal: func(w http.ResponseWriter, r *http.Request) {
			s.PagesHandler.APIV1ServerPrimaryTokenActionHandler(w, r, "reveal")
		},
		TokensPrimaryRotate: func(w http.ResponseWriter, r *http.Request) {
			s.PagesHandler.APIV1ServerPrimaryTokenActionHandler(w, r, "rotate")
		},
		TokensPrimaryRevoke:  s.PagesHandler.APIV1ServerPrimaryTokenRevokeHandler,
		TokensLinkedCreate:   s.PagesHandler.APIV1ServerLinkedTokenCreateHandler,
		TokensLinkedReveal:   s.linkedTokenRouteAction("reveal"),
		TokensLinkedRotate:   s.linkedTokenRouteAction("rotate"),
		TokensLinkedUpdate:   s.linkedTokenRouteAction("update"),
		TokensLinkedRevoke:   s.linkedTokenRouteAction("revoke"),
		Swagger:              s.SwaggerJSONHandler,
		GraphQLGet:           s.GraphQLHandler,
		GraphQLPost:          s.GraphQLHandler,
		Consent:              s.PagesHandler.ConsentHandler,
		CCPA:                 s.PagesHandler.CCPAHandler,
		Dismiss:              s.PagesHandler.DismissAnnouncementHandler,
		MCP:                  mcpHandler.ServeHTTP,
		Healthz:              s.HealthHandler.APIV1HealthzHandler,
		HealthzText:          s.HealthHandler.APIV1HealthzHandler,
		SwaggerAlias:         s.SwaggerJSONHandler,
		GraphQLGetAlias:      s.GraphQLHandler,
		GraphQLPostAlias:     s.GraphQLHandler,
		Autodiscover:         s.autodiscoverHandler(),
		MCPAlias:             mcpHandler.ServeHTTP,
		MCPRootAlias:         mcpHandler.ServeHTTP,
		ServerIndex:          s.PagesHandler.ServerRedirectHandler,
		ServerAbout:          s.PagesHandler.ServerAboutHandler,
		ServerHelp:           s.PagesHandler.ServerHelpHandler,
		ServerHelpMCP:        s.PagesHandler.ServerMCPHelpHandler,
		ServerPrivacy:        s.PagesHandler.ServerPrivacyHandler,
		ServerDPO:            s.PagesHandler.ServerDPOHandler,
		ServerContactGet:     s.PagesHandler.ServerContactHandler,
		ServerContactPost:    s.PagesHandler.ServerContactHandler,
		ServerTrackingScript: s.PagesHandler.ServerTrackingScript,
		ServerTerms:          s.PagesHandler.ServerTermsHandler,
		ServerSecurity:       s.PagesHandler.ServerSecurityHandler,
		ServerSecurityPolicy: s.PagesHandler.ServerSecurityPolicyHandler,
		ServerSecurityThanks: s.PagesHandler.ServerSecurityThanksHandler,
		ServerSecurityReport: func(w http.ResponseWriter, r *http.Request) {
			s.PagesHandler.ServerSecurityReportHandler(w, r, chi.URLParam(r, "tracking_id"))
		},
		ServerConsent:               s.PagesHandler.ConsentHandler,
		ServerCCPA:                  s.PagesHandler.CCPAHandler,
		ServerPreferences:           s.PagesHandler.ServerPreferencesHandler,
		ServerPreferencesPost:       s.PagesHandler.ServerPreferencesUpdateHandler,
		ServerPreferencesTokens:     s.PagesHandler.ServerPreferencesTokensHandler,
		ServerTokenCreate:           s.PagesHandler.ServerPreferencesTokenCreateHandler,
		ServerTokenRestore:          s.PagesHandler.ServerPreferencesTokenRestoreHandler,
		ServerTokenReveal:           s.PagesHandler.ServerPreferencesTokenRevealHandler,
		ServerTokenRotate:           s.PagesHandler.ServerPreferencesTokenRotateHandler,
		ServerTokenForget:           s.PagesHandler.ServerPreferencesTokenForgetHandler,
		ServerTokenRevoke:           s.PagesHandler.ServerPreferencesTokenRevokeHandler,
		ServerLinkedTokenCreate:     s.PagesHandler.ServerPreferencesLinkedTokenCreateHandler,
		ServerLinkedTokenReveal:     linkedTokenPageAction("reveal"),
		ServerLinkedTokenRotate:     linkedTokenPageAction("rotate"),
		ServerLinkedTokenUpdate:     linkedTokenPageAction("update"),
		ServerLinkedTokenRevoke:     linkedTokenPageAction("revoke"),
		ServerPreferencesSync:       s.PagesHandler.ServerPreferencesSyncHandler,
		ServerPreferencesSyncPost:   s.PagesHandler.ServerPreferencesSyncHandler,
		ServerPreferencesSyncImport: s.PagesHandler.ServerPreferencesSyncImportHandler,
		ServerSwagger:               s.SwaggerHandler,
		ServerGraphQLGet:            s.GraphQLHandler,
		ServerGraphQLPost:           s.GraphQLHandler,
		ServerHealth:                s.HealthHandler.HealthzHandler,
		ReportCSP:                   s.reportsHandler("csp"),
		ReportNEL:                   s.reportsHandler("nel"),
		ReportDeprecation:           s.reportsHandler("deprecation"),
		ReportIntervention:          s.reportsHandler("intervention"),
		ReportCrash:                 s.reportsHandler("crash"),
		ReportDefault:               s.reportsHandler("default"),
	}
	if s.HealthzRootEnabled {
		handlers.ServerHealthRoot = s.HealthHandler.HealthzHandler
	}
	geoIPRoute := func(handler appHandler) http.HandlerFunc {
		adapted := appHandlerToHTTP(handler)
		return func(w http.ResponseWriter, r *http.Request) {
			if s.gr == nil || s.gr.IsEmpty() {
				writeNegotiatedError(w, r, http.StatusNotFound, "", i18n.T(r.Context(), "errors.not_found"))
				return
			}
			adapted.ServeHTTP(w, r)
		}
	}
	handlers.CountryRoot = geoIPRoute(s.CLICountryHandler)
	handlers.CountryTxtRoot = geoIPRoute(s.CLICountryHandler)
	handlers.CountryISORoot = geoIPRoute(s.CLICountryISOHandler)
	handlers.CountryISOTxtRoot = geoIPRoute(s.CLICountryISOHandler)
	handlers.CityRoot = geoIPRoute(s.CLICityHandler)
	handlers.CityTxtRoot = geoIPRoute(s.CLICityHandler)
	handlers.CoordinatesRoot = geoIPRoute(s.CLICoordinatesHandler)
	handlers.CoordinatesTxtRoot = geoIPRoute(s.CLICoordinatesHandler)
	handlers.ASNRoot = geoIPRoute(s.CLIASNHandler)
	handlers.ASNTxtRoot = geoIPRoute(s.CLIASNHandler)
	handlers.ASNOrgRoot = geoIPRoute(s.CLIASNOrgHandler)
	handlers.ASNOrgTxtRoot = geoIPRoute(s.CLIASNOrgHandler)
	handlers.Country = geoIPRoute(s.APIV1CountryHandler)
	handlers.City = geoIPRoute(s.APIV1CityHandler)
	handlers.ASN = geoIPRoute(s.APIV1ASNHandler)
	handlers.CountryISO = geoIPRoute(s.APIV1CountryISOHandler)
	handlers.Coordinates = geoIPRoute(s.APIV1CoordinatesHandler)
	handlers.ASNOrg = geoIPRoute(s.APIV1ASNOrgHandler)
	if s.LookupPort != nil {
		handlers.PortRoot = appHandlerToHTTP(s.PortHandler)
		handlers.PortCheck = appHandlerToHTTP(s.PortHandler)
	}
	var registry swagger.Registry
	for _, route := range swagger.RuntimeRouteDefinitions(handlers) {
		if route.Handler == nil {
			continue
		}
		if strings.HasPrefix(route.Path, "/api/") || route.OperationID == "mcpRootAlias" {
			route.Handler = withRouteTextSerializer(route, route.Handler)
		}
		registry.Add(route)
	}
	for _, route := range s.debugRouteDefinitions() {
		registry.Add(route)
	}
	for _, route := range s.torControlRouteDefinitions() {
		registry.Add(route)
	}
	if s.metricsEnabled {
		for _, route := range handler.MetricsRouteDefinitions(s.metricsConfig, "ipgaze", s.auditRejectedCLIToken) {
			registry.Add(route)
		}
	}
	return registry.Routes()
}

// RegisteredAPIRoutes returns the handler-bearing API and diagnostic route
// snapshot mounted by the active router. Documentation, GraphQL, MCP, and
// discovery consume these same route values instead of parallel metadata.
func (s *Server) RegisteredAPIRoutes() []swagger.Route {
	if s == nil {
		return nil
	}
	s.routesMu.RLock()
	defer s.routesMu.RUnlock()
	return append([]swagger.Route(nil), s.activeAPIRoutes...)
}

// linkedTokenRouteAction validates the opaque public ID before forwarding an action.
func (s *Server) linkedTokenRouteAction(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		publicID := chi.URLParam(r, "id")
		if _, err := uuid.Parse(publicID); err != nil {
			handler.SendAPIResponseError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid token id", nil)
			return
		}
		s.PagesHandler.APIV1ServerLinkedTokenActionHandler(w, r, publicID, action)
	}
}
