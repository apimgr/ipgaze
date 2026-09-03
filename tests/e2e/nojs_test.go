//go:build e2e

// Tier 2 of AI.md PART 28 "Browser E2E Testing": a real Chromium with script
// execution switched off at the CDP level. Everything asserted here is what a
// visitor gets with JavaScript disabled, which is the only proof that the
// progressive-enhancement rule of PART 14/16 actually holds.
package e2e

import (
	"context"
	"encoding/base64"
	"net"
	"regexp"
	"strings"
	"testing"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/chromedp"
)

// themeClassPattern reads the active theme off the <html> class attribute.
var themeClassPattern = regexp.MustCompile(`theme-(dark|light|auto)`)

// noJSTab opens a tab with page script execution disabled and a desktop
// viewport, so the whole navigation bar is laid out rather than collapsed.
func noJSTab(t *testing.T) context.Context {
	t.Helper()
	ctx := newBrowserContext(t)
	if err := chromedp.Run(ctx,
		emulation.SetScriptExecutionDisabled(true),
		emulation.SetDeviceMetricsOverride(1280, 900, 1, false),
	); err != nil {
		t.Fatalf("disabling script execution: %v", err)
	}
	return ctx
}

func TestNoJSLandingPageIsFullyUsable(t *testing.T) {
	ctx := noJSTab(t)

	var heading, renderedIP, mainHTML string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(baseURL+"/"),
		chromedp.WaitVisible("#ip-address", chromedp.ByQuery),
		chromedp.Text("h1", &heading, chromedp.ByQuery),
		chromedp.Text("#ip-address", &renderedIP, chromedp.ByQuery),
		chromedp.OuterHTML("main", &mainHTML, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("loading landing page without JavaScript: %v", err)
	}

	if strings.TrimSpace(heading) != "What is my IP address?" {
		t.Errorf("no-JS landing heading is %q", heading)
	}
	if net.ParseIP(strings.TrimSpace(renderedIP)) == nil {
		t.Errorf("no-JS landing page shows %q instead of an IP address", renderedIP)
	}
	if !strings.Contains(mainHTML, "IP Address") {
		saveArtifact(t, "nojs-landing-main.html", []byte(mainHTML))
		t.Error("no-JS landing page is missing its IP Address detail row")
	}
}

func TestNoJSConfirmsScriptEnhancementsAreInert(t *testing.T) {
	ctx := noJSTab(t)

	// The copy button's feedback is pure JavaScript enhancement. With
	// scripts disabled the click must be a no-op, which simultaneously
	// proves this tier really is running without JavaScript.
	var classAfterClick string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(baseURL+"/"),
		chromedp.WaitVisible(".copy-btn", chromedp.ByQuery),
		chromedp.Click(".copy-btn", chromedp.ByQuery),
		chromedp.AttributeValue(".copy-btn", "class", &classAfterClick, nil, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("clicking the copy button without JavaScript: %v", err)
	}
	if strings.Contains(classAfterClick, "copied") {
		t.Fatalf("copy button reacted with class %q, so page scripts are still running in the Tier 2 tab", classAfterClick)
	}
}

func TestNoJSNavigationLinksWork(t *testing.T) {
	ctx := noJSTab(t)

	var location, heading string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(baseURL+"/"),
		chromedp.WaitVisible(`.nav-links a[href="/server/about"]`, chromedp.ByQuery),
		chromedp.Click(`.nav-links a[href="/server/about"]`, chromedp.ByQuery),
		chromedp.WaitVisible("h1", chromedp.ByQuery),
		chromedp.Location(&location),
		chromedp.Text("h1", &heading, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("following the About link without JavaScript: %v", err)
	}
	if location != baseURL+"/server/about" {
		t.Errorf("About link landed on %q, want %s/server/about", location, baseURL)
	}
	if strings.TrimSpace(heading) == "" {
		t.Error("About page rendered no heading without JavaScript")
	}
}

func TestNoJSThemeToggleIsANativeFormPost(t *testing.T) {
	ctx := noJSTab(t)

	var before, after, location string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(baseURL+"/"),
		chromedp.WaitVisible(".theme-toggle-form button[type=submit]", chromedp.ByQuery),
		chromedp.AttributeValue("html", "class", &before, nil, chromedp.ByQuery),
		chromedp.Click(".theme-toggle-form button[type=submit]", chromedp.ByQuery),
		chromedp.WaitVisible("#ip-address", chromedp.ByQuery),
		chromedp.AttributeValue("html", "class", &after, nil, chromedp.ByQuery),
		chromedp.Location(&location),
	); err != nil {
		t.Fatalf("submitting the theme form without JavaScript: %v", err)
	}

	beforeTheme := themeClassPattern.FindString(before)
	afterTheme := themeClassPattern.FindString(after)
	if beforeTheme == "" || afterTheme == "" {
		t.Fatalf("theme class missing: before=%q after=%q", before, after)
	}
	if beforeTheme == afterTheme {
		t.Errorf("theme did not change without JavaScript: still %s", afterTheme)
	}
	// The POST redirects back to the page it came from, so the visitor
	// stays on the landing page instead of a bare confirmation.
	if location != baseURL+"/" {
		t.Errorf("theme form POST left the visitor on %q, want %s/", location, baseURL)
	}
}

func TestNoJSPreferencesImportFormAppliesThemeAndLanguage(t *testing.T) {
	ctx := noJSTab(t)

	code := base64.RawURLEncoding.EncodeToString([]byte("theme=light&lang=es"))

	var htmlClass, langAttr, heading string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(baseURL+"/server/preferences"),
		chromedp.WaitVisible("#preferences-import-code", chromedp.ByQuery),
		chromedp.SendKeys("#preferences-import-code", code, chromedp.ByQuery),
		chromedp.Click(`form[action="/server/preferences/import"] button[type=submit]`, chromedp.ByQuery),
		chromedp.WaitVisible("#preferences-export-code", chromedp.ByQuery),
		chromedp.AttributeValue("html", "class", &htmlClass, nil, chromedp.ByQuery),
		chromedp.AttributeValue("html", "lang", &langAttr, nil, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("submitting the preferences import form without JavaScript: %v", err)
	}
	if themeClassPattern.FindString(htmlClass) != "theme-light" {
		t.Errorf("imported theme not applied, <html> class is %q", htmlClass)
	}
	if langAttr != "es" {
		t.Errorf("imported language not applied, <html> lang is %q", langAttr)
	}

	// The imported language must survive to the next plain navigation.
	if err := chromedp.Run(ctx,
		chromedp.Navigate(baseURL+"/"),
		chromedp.WaitVisible("h1", chromedp.ByQuery),
		chromedp.Text("h1", &heading, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("reloading the landing page after import: %v", err)
	}
	if strings.TrimSpace(heading) != "¿Cuál es mi dirección IP?" {
		t.Errorf("landing heading after Spanish import is %q", heading)
	}
}

func TestNoJSSpecificIPLookupRoutesAreReachable(t *testing.T) {
	ctx := noJSTab(t)

	// The echoip-compatible /{ip}/{field} route is a plain URL, so it must
	// answer with the looked-up address even in a scriptless browser.
	var bodyText string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(baseURL+"/8.8.8.8/ip"),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Text("body", &bodyText, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("looking up a specific IP without JavaScript: %v", err)
	}
	if strings.TrimSpace(bodyText) != "8.8.8.8" {
		t.Errorf("/8.8.8.8/ip rendered %q, want 8.8.8.8", strings.TrimSpace(bodyText))
	}
}

func TestNoJSErrorPageRenders(t *testing.T) {
	ctx := noJSTab(t)

	var title, containerHTML string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(baseURL+"/this-page-does-not-exist"),
		chromedp.WaitVisible(".error-title", chromedp.ByQuery),
		chromedp.Text(".error-title", &title, chromedp.ByQuery),
		chromedp.OuterHTML(".error-container", &containerHTML, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("rendering the 404 page without JavaScript: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(title), "404") {
		t.Errorf("404 page title element reads %q", title)
	}
	if !strings.Contains(containerHTML, `href="/"`) {
		saveArtifact(t, "nojs-404.html", []byte(containerHTML))
		t.Error("404 page offers no link back to the landing page")
	}
}
