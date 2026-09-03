//go:build e2e

// Tier 3 of AI.md PART 28 "Browser E2E Testing": a real Chromium with
// JavaScript enabled. These tests cover the enhanced behaviour layered on top
// of the server-rendered pages, plus the universal requirements the spec puts
// on every project — zero console errors, zero failed asset requests, working
// theme switching with real computed-style changes, and a usable 375x812
// mobile layout.
package e2e

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

// pageWatcher collects the console errors and failed network requests a page
// produced, which are the two "zero tolerance" signals of Tier 3.
type pageWatcher struct {
	mu             sync.Mutex
	consoleErrors  []string
	failedRequests []string
	requestURLs    map[network.RequestID]string
}

// watchPage subscribes to the console and network events of a tab. Call it
// before the first navigation so nothing is missed.
func watchPage(t *testing.T, ctx context.Context) *pageWatcher {
	t.Helper()
	watcher := &pageWatcher{requestURLs: map[network.RequestID]string{}}

	chromedp.ListenTarget(ctx, func(event any) {
		switch ev := event.(type) {
		case *runtime.EventExceptionThrown:
			watcher.mu.Lock()
			watcher.consoleErrors = append(watcher.consoleErrors, ev.ExceptionDetails.Error())
			watcher.mu.Unlock()
		case *runtime.EventConsoleAPICalled:
			if ev.Type != runtime.APITypeError && ev.Type != runtime.APITypeAssert {
				return
			}
			parts := make([]string, 0, len(ev.Args))
			for _, arg := range ev.Args {
				parts = append(parts, string(arg.Value))
			}
			watcher.mu.Lock()
			watcher.consoleErrors = append(watcher.consoleErrors, strings.Join(parts, " "))
			watcher.mu.Unlock()
		case *network.EventRequestWillBeSent:
			watcher.mu.Lock()
			watcher.requestURLs[ev.RequestID] = ev.Request.URL
			watcher.mu.Unlock()
		case *network.EventResponseReceived:
			if ev.Response.Status < 400 {
				return
			}
			watcher.mu.Lock()
			watcher.failedRequests = append(watcher.failedRequests,
				fmt.Sprintf("%s -> HTTP %d", ev.Response.URL, ev.Response.Status))
			watcher.mu.Unlock()
		case *network.EventLoadingFailed:
			watcher.mu.Lock()
			url := watcher.requestURLs[ev.RequestID]
			if url != "" && !ev.Canceled {
				watcher.failedRequests = append(watcher.failedRequests,
					fmt.Sprintf("%s -> %s", url, ev.ErrorText))
			}
			watcher.mu.Unlock()
		}
	})

	if err := chromedp.Run(ctx, network.Enable()); err != nil {
		t.Fatalf("enabling network events: %v", err)
	}
	return watcher
}

// report fails the test with everything the watcher saw on the given page.
func (w *pageWatcher) report(t *testing.T, page string) {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, message := range w.consoleErrors {
		t.Errorf("%s: console error: %s", page, message)
	}
	for _, message := range w.failedRequests {
		t.Errorf("%s: failed request: %s", page, message)
	}
}

// reset clears collected events so one tab can be reused across pages.
func (w *pageWatcher) reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.consoleErrors = nil
	w.failedRequests = nil
}

func TestBrowserEveryPageLoadsCleanly(t *testing.T) {
	ctx := newBrowserContext(t)
	watcher := watchPage(t, ctx)

	pages := []string{
		"/",
		"/server/about",
		"/server/help",
		"/server/privacy",
		"/server/terms",
		"/server/contact",
		"/server/healthz",
		"/server/preferences",
		"/server/docs/swagger",
		"/server/docs/graphql",
	}

	for _, page := range pages {
		watcher.reset()
		if err := chromedp.Run(ctx,
			chromedp.Navigate(baseURL+page),
			chromedp.WaitVisible("main", chromedp.ByQuery),
			// The app script registers the service worker and wires up
			// enhancements asynchronously; give it a beat to fail loudly
			// if it is going to.
			chromedp.Sleep(500*time.Millisecond),
		); err != nil {
			t.Errorf("loading %s with JavaScript: %v", page, err)
			continue
		}
		watcher.report(t, page)
	}
}

func TestBrowserLandingPageRendersEnhancedContent(t *testing.T) {
	ctx := newBrowserContext(t)

	var heading, ipText string
	var hasToastContainer bool
	if err := chromedp.Run(ctx,
		chromedp.Navigate(baseURL+"/"),
		chromedp.WaitVisible("#ip-address", chromedp.ByQuery),
		chromedp.Text("h1", &heading, chromedp.ByQuery),
		chromedp.Text("#ip-address", &ipText, chromedp.ByQuery),
		chromedp.Evaluate(`document.getElementById('toast-container') !== null`, &hasToastContainer),
	); err != nil {
		t.Fatalf("loading the landing page: %v", err)
	}
	if strings.TrimSpace(heading) != "What is my IP address?" {
		t.Errorf("landing heading is %q", heading)
	}
	if strings.TrimSpace(ipText) == "" {
		t.Error("landing page rendered no IP address")
	}
	if !hasToastContainer {
		t.Error("toast container is missing, so JavaScript enhancements have nowhere to render")
	}
}

func TestBrowserCopyButtonGivesFeedback(t *testing.T) {
	ctx := newBrowserContext(t)

	var expectedLabel, classAfter, labelAfter string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(baseURL+"/"),
		chromedp.WaitVisible(".copy-btn", chromedp.ByQuery),
		chromedp.AttributeValue(".copy-btn", "data-copied-label", &expectedLabel, nil, chromedp.ByQuery),
		chromedp.Click(".copy-btn", chromedp.ByQuery),
		chromedp.Sleep(300*time.Millisecond),
		chromedp.AttributeValue(".copy-btn", "class", &classAfter, nil, chromedp.ByQuery),
		chromedp.Text(".copy-btn .copy-text", &labelAfter, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("clicking the copy button: %v", err)
	}
	if !strings.Contains(classAfter, "copied") {
		t.Errorf("copy button class after click is %q, want it to include \"copied\"", classAfter)
	}
	if strings.TrimSpace(labelAfter) != strings.TrimSpace(expectedLabel) {
		t.Errorf("copy button label after click is %q, want %q", labelAfter, expectedLabel)
	}
}

func TestBrowserThemeToggleChangesComputedStyle(t *testing.T) {
	ctx := newBrowserContext(t)

	var classBefore, classAfter, colorBefore, colorAfter string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(baseURL+"/"),
		chromedp.WaitVisible(".theme-toggle-form button[type=submit]", chromedp.ByQuery),
		chromedp.AttributeValue("html", "class", &classBefore, nil, chromedp.ByQuery),
		chromedp.Evaluate(`getComputedStyle(document.body).backgroundColor`, &colorBefore),
		chromedp.Click(".theme-toggle-form button[type=submit]", chromedp.ByQuery),
		chromedp.Sleep(500*time.Millisecond),
		chromedp.AttributeValue("html", "class", &classAfter, nil, chromedp.ByQuery),
		chromedp.Evaluate(`getComputedStyle(document.body).backgroundColor`, &colorAfter),
	); err != nil {
		t.Fatalf("toggling the theme with JavaScript: %v", err)
	}

	if themeClassPattern.FindString(classBefore) == themeClassPattern.FindString(classAfter) {
		t.Fatalf("theme class did not change: %q", classAfter)
	}
	if colorBefore == colorAfter {
		t.Errorf("theme changed from %q to %q but the computed body background stayed %q",
			classBefore, classAfter, colorAfter)
	}
}

func TestBrowserEveryThemeRendersDistinctly(t *testing.T) {
	ctx := newBrowserContext(t)

	colors := map[string]string{}
	for _, theme := range []string{"dark", "light", "auto"} {
		var htmlClass, color string
		if err := chromedp.Run(ctx,
			chromedp.Navigate(fmt.Sprintf("%s/server/preferences/import?theme=%s", baseURL, theme)),
			chromedp.WaitVisible("main", chromedp.ByQuery),
			chromedp.AttributeValue("html", "class", &htmlClass, nil, chromedp.ByQuery),
			chromedp.Evaluate(`getComputedStyle(document.body).backgroundColor`, &color),
		); err != nil {
			t.Fatalf("applying theme %s: %v", theme, err)
		}
		if want := "theme-" + theme; !strings.Contains(htmlClass, want) {
			t.Errorf("after importing theme %s the <html> class is %q, want it to include %q", theme, htmlClass, want)
		}
		if strings.TrimSpace(color) == "" {
			t.Errorf("theme %s produced no computed body background colour", theme)
		}
		colors[theme] = color
	}
	if colors["dark"] == colors["light"] {
		t.Errorf("dark and light themes both compute to background %q", colors["dark"])
	}
}

func TestBrowserLanguageSwitchingChangesRenderedStrings(t *testing.T) {
	ctx := newBrowserContext(t)

	var english, spanish, langAttr string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(baseURL+"/server/preferences/import?lang=en"),
		chromedp.Navigate(baseURL+"/"),
		chromedp.WaitVisible("h1", chromedp.ByQuery),
		chromedp.Text("h1", &english, chromedp.ByQuery),
		chromedp.Navigate(baseURL+"/server/preferences/import?lang=es"),
		chromedp.Navigate(baseURL+"/"),
		chromedp.WaitVisible("h1", chromedp.ByQuery),
		chromedp.Text("h1", &spanish, chromedp.ByQuery),
		chromedp.AttributeValue("html", "lang", &langAttr, nil, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("switching language: %v", err)
	}
	if strings.TrimSpace(english) == strings.TrimSpace(spanish) {
		t.Errorf("landing heading is %q in both English and Spanish", english)
	}
	if langAttr != "es" {
		t.Errorf("<html lang> is %q after switching to Spanish", langAttr)
	}
	if strings.TrimSpace(spanish) != "¿Cuál es mi dirección IP?" {
		t.Errorf("Spanish landing heading is %q", spanish)
	}
}

func TestBrowserMobileViewportHasNoHorizontalScroll(t *testing.T) {
	ctx := newBrowserContext(t)
	if err := chromedp.Run(ctx, emulation.SetDeviceMetricsOverride(375, 812, 3, true)); err != nil {
		t.Fatalf("applying the 375x812 viewport: %v", err)
	}

	for _, page := range []string{"/", "/server/about", "/server/preferences", "/server/healthz"} {
		var overflow int64
		var burgerVisible bool
		if err := chromedp.Run(ctx,
			chromedp.Navigate(baseURL+page),
			chromedp.WaitVisible("main", chromedp.ByQuery),
			chromedp.Evaluate(`document.documentElement.scrollWidth - document.documentElement.clientWidth`, &overflow),
			chromedp.Evaluate(`(() => {
				const burger = document.querySelector('.nav-burger');
				if (!burger) { return false; }
				const box = burger.getBoundingClientRect();
				return box.width > 0 && box.height > 0;
			})()`, &burgerVisible),
		); err != nil {
			t.Errorf("loading %s at 375x812: %v", page, err)
			continue
		}
		if overflow > 0 {
			t.Errorf("%s scrolls horizontally by %dpx at 375x812", page, overflow)
		}
		if !burgerVisible {
			t.Errorf("%s has no usable navigation control at 375x812", page)
		}
	}
}

func TestBrowserAPIDocsPagesInitialise(t *testing.T) {
	ctx := newBrowserContext(t)

	var swaggerMount, graphiqlMount bool
	if err := chromedp.Run(ctx,
		chromedp.Navigate(baseURL+"/server/docs/swagger"),
		chromedp.WaitVisible("#swagger-ui", chromedp.ByQuery),
		chromedp.Evaluate(`document.querySelector('#swagger-ui').dataset.specUrl !== undefined`, &swaggerMount),
		chromedp.Navigate(baseURL+"/server/docs/graphql"),
		chromedp.WaitVisible("main", chromedp.ByQuery),
		chromedp.Evaluate(`document.querySelector('#graphiql') !== null || document.body.innerHTML.includes('graphql')`, &graphiqlMount),
	); err != nil {
		t.Fatalf("loading the API documentation pages: %v", err)
	}
	if !swaggerMount {
		t.Error("Swagger UI mount point carries no data-spec-url, so it can never fetch a spec")
	}
	if !graphiqlMount {
		t.Error("GraphiQL page rendered without a GraphQL surface")
	}
}

func TestBrowserErrorPageIsThemedNotBlank(t *testing.T) {
	ctx := newBrowserContext(t)

	var title string
	var bodyLength int64
	var background string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(baseURL+"/definitely-not-a-real-page"),
		chromedp.WaitVisible(".error-title", chromedp.ByQuery),
		chromedp.Text(".error-title", &title, chromedp.ByQuery),
		chromedp.Evaluate(`document.body.innerText.trim().length`, &bodyLength),
		chromedp.Evaluate(`getComputedStyle(document.body).backgroundColor`, &background),
	); err != nil {
		t.Fatalf("loading the 404 page: %v", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(title), "404") {
		t.Errorf("404 page heading is %q", title)
	}
	if bodyLength < 20 {
		t.Errorf("404 page body holds only %d characters of text", bodyLength)
	}
	if strings.TrimSpace(background) == "" || background == "rgba(0, 0, 0, 0)" {
		t.Errorf("404 page is unthemed, computed background is %q", background)
	}
}
