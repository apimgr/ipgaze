package server

import (
	"bytes"
	"encoding/json"
	htmltemplate "html/template"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/apimgr/ipgaze/src/config"
	"github.com/apimgr/ipgaze/src/server/handler"
)

// imgTagPattern matches a complete image tag so each one can be checked for
// an alt attribute, as required by AI.md PART 30.
var imgTagPattern = regexp.MustCompile(`(?is)<img\b[^>]*>`)

// accessibilityMarkers are the WCAG 2.1 AA structural requirements from
// AI.md PART 30 that every rendered page must carry: both skip links as the
// first focusable elements, and the banner/navigation/main/contentinfo
// landmark set.
var accessibilityMarkers = []struct {
	name    string
	snippet string
}{
	{"skip link to main content", `href="#main-content" class="skip-link"`},
	{"skip link to navigation", `href="#navigation" class="skip-link"`},
	{"banner landmark", `role="banner"`},
	{"navigation landmark", `role="navigation"`},
	{"navigation skip target", `id="navigation"`},
	{"main landmark", `role="main"`},
	{"main skip target", `id="main-content"`},
	{"contentinfo landmark", `role="contentinfo"`},
}

// assertAccessibleDocument checks one rendered HTML document against the
// PART 30 requirements: language and direction attributes, skip links,
// landmarks and image alt text.
func assertAccessibleDocument(t *testing.T, page, body string) {
	t.Helper()

	if !strings.Contains(body, `lang="en"`) {
		t.Errorf("%s: missing lang attribute on the html element", page)
	}
	if !strings.Contains(body, `dir="ltr"`) {
		t.Errorf("%s: missing dir attribute on the html element", page)
	}

	for _, marker := range accessibilityMarkers {
		if !strings.Contains(body, marker.snippet) {
			t.Errorf("%s: missing %s [%s]", page, marker.name, marker.snippet)
		}
	}

	// The skip links must precede the navigation they skip past, otherwise
	// they are not the first focusable elements in the document.
	firstSkip := strings.Index(body, `class="skip-link"`)
	navStart := strings.Index(body, `id="navigation"`)
	if firstSkip < 0 || navStart < 0 || firstSkip > navStart {
		t.Errorf("%s: skip links must appear before the navigation landmark", page)
	}

	for _, tag := range imgTagPattern.FindAllString(body, -1) {
		if !strings.Contains(tag, "alt=") {
			t.Errorf("%s: image without alt text: %s", page, tag)
		}
	}
}

func assertLayoutStructure(t *testing.T, page, source string) {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(source))
	if err != nil {
		t.Fatalf("parse %s: %v", page, err)
	}
	var body *html.Node
	for node := doc.FirstChild; node != nil; node = node.NextSibling {
		if found := findElement(node, "body"); found != nil {
			body = found
			break
		}
	}
	if body == nil {
		t.Fatalf("%s: body element not found", page)
	}

	positions := map[string]int{"main-content": -1, "nav-panel": -1, "nav-overlay": -1}
	position, h1Count, cardCount := 0, 0, 0
	for child := body.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.ElementNode {
			if id := elementAttribute(child, "id"); id == "main-content" || id == "nav-panel" {
				positions[id] = position
			}
			if hasClass(child, "nav-overlay") {
				positions["nav-overlay"] = position
			}
		}
		position++
	}
	if toggle := findElementByID(doc, "nav-toggle"); toggle == nil || toggle.Parent != body {
		t.Errorf("%s: navigation checkbox is not a direct body child", page)
	}
	if panel := findElementByID(doc, "nav-panel"); panel == nil || panel.Parent != body {
		t.Errorf("%s: navigation drawer is not a direct body child", page)
	}
	if overlay := findElementByClass(doc, "nav-overlay"); overlay == nil || overlay.Parent != body {
		t.Errorf("%s: navigation scrim is not a direct body child", page)
	}
	countLayoutHeadings(body, &h1Count, &cardCount, t, page)
	if h1Count != 1 {
		t.Errorf("%s: rendered %d h1 headings, want exactly one", page, h1Count)
	}
	if positions["main-content"] < 0 || positions["nav-panel"] <= positions["main-content"] || positions["nav-overlay"] <= positions["main-content"] {
		t.Errorf("%s: navigation drawer must be a body sibling after main", page)
	}
	if cardCount == 0 {
		t.Errorf("%s: rendered no section cards", page)
	}
}

func assertPageConformance(t *testing.T, page, source string) {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(source))
	if err != nil {
		t.Fatalf("parse %s: %v", page, err)
	}
	counts := map[string]int{"main": 0, "h1": 0}
	previousHeadingLevel := 0
	var walk func(*html.Node, *html.Node)
	walk = func(node, parent *html.Node) {
		if node.Type == html.ElementNode {
			counts[node.Data]++
			if len(node.Data) == 2 && node.Data[0] == 'h' && node.Data[1] >= '1' && node.Data[1] <= '6' {
				level := int(node.Data[1] - '0')
				if previousHeadingLevel > 0 && level > previousHeadingLevel+1 {
					t.Errorf("%s: heading level jumps from h%d to h%d", page, previousHeadingLevel, level)
				}
				previousHeadingLevel = level
			}
			if node.Data == "style" {
				t.Errorf("%s: inline style element is forbidden", page)
			}
			if node.Data == "script" && elementAttribute(node, "type") != "application/ld+json" && strings.TrimSpace(nodeText(node)) != "" {
				t.Errorf("%s: executable inline script body is forbidden", page)
			}
			for _, attr := range node.Attr {
				name := strings.ToLower(attr.Key)
				if name == "style" {
					t.Errorf("%s: inline style attribute is forbidden", page)
				}
				if strings.HasPrefix(name, "on") {
					t.Errorf("%s: inline event attribute %q is forbidden", page, name)
				}
			}
			if node.Data == "img" && !hasAttribute(node, "alt") {
				t.Errorf("%s: image is missing alt text", page)
			}
			if node.Data == "form" && strings.EqualFold(elementAttribute(node, "method"), "post") && findNamedInput(node, "csrf_token") == nil {
				t.Errorf("%s: POST form %q is missing csrf_token", page, elementAttribute(node, "action"))
			}
			if node.Data == "table" {
				if findElement(node, "thead") == nil {
					t.Errorf("%s: table is missing a thead", page)
				}
				if !hasClass(node, "data-table") {
					t.Errorf("%s: table is missing the data-table class", page)
				}
				if !hasAncestorClass(parent, "table-wrapper") {
					t.Errorf("%s: table is outside .table-wrapper", page)
				}
				if thead := findElement(node, "thead"); thead != nil {
					assertColumnHeaderScopes(t, page, thead)
				}
			}
			if page != "index.tmpl" && node.Data == "h1" && !hasClass(node, "page-title") {
				t.Errorf("%s: h1 is missing the page-title class", page)
			}
			if isFormControl(node) && elementAttribute(node, "type") != "hidden" && !hasAssociatedLabel(doc, node) {
				t.Errorf("%s: form control %q has no associated label", page, elementAttribute(node, "id"))
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child, node)
		}
	}
	walk(doc, nil)
	if counts["main"] != 1 {
		t.Errorf("%s: rendered %d main elements, want exactly one", page, counts["main"])
	}
	if counts["h1"] != 1 {
		t.Errorf("%s: rendered %d h1 elements, want exactly one", page, counts["h1"])
	}
	body := findElement(doc, "body")
	firstElements := directElementChildren(body)
	if len(firstElements) < 2 || firstElements[0].Data != "a" || !hasClass(firstElements[0], "skip-link") || firstElements[1].Data != "a" || !hasClass(firstElements[1], "skip-link") {
		t.Errorf("%s: the two skip links must be the first body elements", page)
	}
	assertHeaderConformance(t, page, doc)
}

func assertColumnHeaderScopes(t *testing.T, page string, thead *html.Node) {
	t.Helper()
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "th" && elementAttribute(node, "scope") != "col" {
			t.Errorf("%s: table column header is missing scope=\"col\"", page)
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(thead)
}

func assertHeaderConformance(t *testing.T, page string, doc *html.Node) {
	t.Helper()
	var banner *html.Node
	var findBanner func(*html.Node)
	findBanner = func(node *html.Node) {
		if banner != nil {
			return
		}
		if node.Type == html.ElementNode && node.Data == "header" && elementAttribute(node, "role") == "banner" {
			banner = node
			return
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			findBanner(child)
		}
	}
	findBanner(doc)
	if banner == nil {
		t.Errorf("%s: site banner header is missing", page)
		return
	}
	children := directElementChildren(banner)
	if len(children) < 4 || len(children) > 5 {
		t.Errorf("%s: header has %d top-level elements, want four plus optional branding fragment", page, len(children))
		return
	}
	if children[0].Data != "a" || !hasClass(children[0], "site-brand") || elementAttribute(children[0], "href") != "/" {
		t.Errorf("%s: header must begin with the project brand link", page)
	}
	if children[1].Data != "nav" || !hasClass(children[1], "nav-links") {
		t.Errorf("%s: brand must be followed by nav.nav-links", page)
	}
	if children[2].Data != "label" || !hasClass(children[2], "nav-burger") {
		t.Errorf("%s: nav links must be followed by the hamburger label", page)
	}
	if children[3].Data != "div" || !hasClass(children[3], "header-actions") {
		t.Errorf("%s: hamburger must be followed by .header-actions", page)
	} else {
		actions := directElementChildren(children[3])
		if len(actions) != 2 || actions[0].Data != "a" || actions[1].Data != "form" || !hasClass(actions[1], "theme-toggle-form") {
			t.Errorf("%s: header actions must contain only preferences link then theme form", page)
		}
	}
	if len(children) == 5 && !hasClass(children[4], "operator-header-fragment") {
		t.Errorf("%s: operator header content must be last", page)
	}
	for _, child := range directElementChildren(children[1]) {
		if child.Data != "a" {
			t.Errorf("%s: desktop navigation may contain only plain links", page)
		}
	}
	for _, child := range directElementChildren(findElementByID(doc, "nav-panel")) {
		if child.Data != "a" {
			t.Errorf("%s: mobile drawer may contain only navigation links", page)
		}
	}
}

func TestHeaderBrandingFragmentPlacement(t *testing.T) {
	render := NewPageRenderer("0.0.0-testcommit")
	page := func(data handler.PageData) string {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/server/about", nil)
		if err := render(rec, req, "about.tmpl", data); err != nil {
			t.Fatalf("render about page: %v", err)
		}
		return rec.Body.String()
	}
	plain := page(testPageData())
	data := testPageData()
	data.OperatorContents = map[string]htmltemplate.HTML{"header": `<span class="operator-header-fragment">Operator notice</span>`}
	branded := page(data)
	plainDoc, err := html.Parse(strings.NewReader(plain))
	if err != nil {
		t.Fatal(err)
	}
	brandedDoc, err := html.Parse(strings.NewReader(branded))
	if err != nil {
		t.Fatal(err)
	}
	plainHeader := findRole(plainDoc, "banner")
	brandedHeader := findRole(brandedDoc, "banner")
	if plainHeader == nil || brandedHeader == nil {
		t.Fatal("rendered header is missing")
	}
	plainCore := directElementChildren(plainHeader)
	brandedCore := directElementChildren(brandedHeader)
	if len(plainCore) != 4 || len(brandedCore) != 5 || !hasClass(brandedCore[4], "operator-header-fragment") {
		t.Fatalf("header fragment was not appended as the last child: plain=%d branded=%d", len(plainCore), len(brandedCore))
	}
	for index := range plainCore {
		var plainHTML, brandedHTML bytes.Buffer
		if err := html.Render(&plainHTML, plainCore[index]); err != nil {
			t.Fatal(err)
		}
		if err := html.Render(&brandedHTML, brandedCore[index]); err != nil {
			t.Fatal(err)
		}
		if plainHTML.String() != brandedHTML.String() {
			t.Errorf("branding fragment changed header child %d", index)
		}
	}
}

func TestHubRegistryPagesAreRenderedAndListedOnce(t *testing.T) {
	ts := httptest.NewServer(testServer().Handler())
	defer ts.Close()
	paths := handler.RegisteredHubPagePaths()
	hubBodies := map[string]string{}
	for _, hub := range []string{"/server/help", "/server/preferences"} {
		req, err := http.NewRequest(http.MethodGet, ts.URL+hub, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept", "text/html")
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible browser)")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if res.StatusCode != http.StatusOK {
			t.Fatalf("GET %s returned %d, want 200", hub, res.StatusCode)
		}
		hubBodies[hub] = string(body)
		assertPageConformance(t, hub, string(body))
		assertBreadcrumbConformance(t, hub, string(body), "")
	}
	for _, path := range paths {
		req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept", "text/html")
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible browser)")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if res.StatusCode != http.StatusOK || !strings.Contains(res.Header.Get("Content-Type"), "text/html") {
			t.Errorf("registered page %s returned status=%d content-type=%q", path, res.StatusCode, res.Header.Get("Content-Type"))
		} else {
			assertPageConformance(t, path, string(body))
		}
		hub := "/server/preferences"
		if strings.HasPrefix(path, "/server/help/") {
			hub = "/server/help"
		}
		assertBreadcrumbConformance(t, path, string(body), hub)
		if got := strings.Count(hubBodies[hub], `href="`+path+`"`); got != 1 {
			t.Errorf("hub %s links registered page %s %d times, want once", hub, path, got)
		}
	}
	apiReq, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/server/help", nil)
	if err != nil {
		t.Fatal(err)
	}
	apiReq.Header.Set("Accept", "application/json")
	apiRes, err := http.DefaultClient.Do(apiReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = apiRes.Body.Close() }()
	var envelope struct {
		Data struct {
			Pages []handler.HubPage `json:"pages"`
		} `json:"data"`
	}
	if err := json.NewDecoder(apiRes.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if !strings.HasPrefix(path, "/server/help/") {
			continue
		}
		count := 0
		for _, page := range envelope.Data.Pages {
			if page.Path == path {
				count++
			}
		}
		if count != 1 {
			t.Errorf("help JSON lists registered page %s %d times, want once", path, count)
		}
	}
}

func assertBreadcrumbConformance(t *testing.T, page, source, hub string) {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(source))
	if err != nil {
		t.Fatalf("parse %s breadcrumb: %v", page, err)
	}
	var breadcrumbs []*html.Node
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode && hasClass(node, "breadcrumb") {
			breadcrumbs = append(breadcrumbs, node)
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	if hub == "" {
		if len(breadcrumbs) != 0 {
			t.Errorf("%s: hub page has %d breadcrumbs, want none", page, len(breadcrumbs))
		}
		return
	}
	if len(breadcrumbs) != 1 {
		t.Errorf("%s: sub-page has %d breadcrumbs, want exactly one", page, len(breadcrumbs))
		return
	}
	links := nestedLinks(breadcrumbs[0])
	if len(links) != 1 || elementAttribute(links[0], "href") != hub {
		t.Errorf("%s: breadcrumb must contain one link to %s", page, hub)
	}
}

func nestedLinks(node *html.Node) []*html.Node {
	var links []*html.Node
	var walk func(*html.Node)
	walk = func(current *html.Node) {
		if current.Type == html.ElementNode && current.Data == "a" {
			links = append(links, current)
		}
		for child := current.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(node)
	return links
}

func TestErrorAndHealthFallbackPagesConform(t *testing.T) {
	t.Run("rendered not found page", func(t *testing.T) {
		ts := httptest.NewServer(testServer().Handler())
		defer ts.Close()
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/page-that-does-not-exist", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept", "text/html")
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible browser)")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		assertPageConformance(t, "404 page", string(body))
	})
	t.Run("guaranteed error response", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/broken", nil)
		rec := httptest.NewRecorder()
		handler.WriteErrorHTML(rec, req, http.StatusInternalServerError, "Internal Server Error")
		assertPageConformance(t, "500 fallback", rec.Body.String())
	})
	t.Run("health page fallback", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/server/healthz", nil)
		req.Header.Set("Accept", "text/html")
		rec := httptest.NewRecorder()
		(&handler.HealthHandler{}).HealthzHandler(rec, req)
		assertPageConformance(t, "healthz fallback", rec.Body.String())
	})
}

func findRole(node *html.Node, role string) *html.Node {
	if node.Type == html.ElementNode && elementAttribute(node, "role") == role {
		return node
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if found := findRole(child, role); found != nil {
			return found
		}
	}
	return nil
}

func directElementChildren(node *html.Node) []*html.Node {
	if node == nil {
		return nil
	}
	children := make([]*html.Node, 0)
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.ElementNode {
			children = append(children, child)
		}
	}
	return children
}

func nodeText(node *html.Node) string {
	if node.Type == html.TextNode {
		return node.Data
	}
	var text strings.Builder
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		text.WriteString(nodeText(child))
	}
	return text.String()
}

func hasAttribute(node *html.Node, name string) bool {
	for _, attr := range node.Attr {
		if attr.Key == name {
			return true
		}
	}
	return false
}

func findNamedInput(node *html.Node, name string) *html.Node {
	if node.Type == html.ElementNode && node.Data == "input" && elementAttribute(node, "name") == name {
		return node
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if found := findNamedInput(child, name); found != nil {
			return found
		}
	}
	return nil
}

func isFormControl(node *html.Node) bool {
	if node.Type != html.ElementNode {
		return false
	}
	switch node.Data {
	case "input", "select", "textarea":
		return true
	default:
		return false
	}
}

func hasAssociatedLabel(doc, control *html.Node) bool {
	if strings.TrimSpace(elementAttribute(control, "aria-label")) != "" {
		return true
	}
	for _, id := range strings.Fields(elementAttribute(control, "aria-labelledby")) {
		if label := findElementByID(doc, id); label != nil && strings.TrimSpace(nodeText(label)) != "" {
			return true
		}
	}
	id := elementAttribute(control, "id")
	if id != "" {
		var findLabel func(*html.Node) bool
		findLabel = func(node *html.Node) bool {
			if node.Type == html.ElementNode && node.Data == "label" && elementAttribute(node, "for") == id {
				return true
			}
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				if findLabel(child) {
					return true
				}
			}
			return false
		}
		if findLabel(doc) {
			return true
		}
	}
	for parent := control.Parent; parent != nil; parent = parent.Parent {
		if parent.Type == html.ElementNode && parent.Data == "label" {
			return true
		}
	}
	return false
}

func hasAncestorClass(node *html.Node, class string) bool {
	for ; node != nil; node = node.Parent {
		if node.Type == html.ElementNode && hasClass(node, class) {
			return true
		}
	}
	return false
}

func countLayoutHeadings(node *html.Node, h1Count, cardCount *int, t *testing.T, page string) {
	if node.Type == html.ElementNode {
		if node.Data == "h1" {
			*h1Count++
		}
		if hasClass(node, "section-card") {
			count := countDescendantHeadings(node, "h2")
			if count != 1 {
				t.Errorf("%s: section card contains %d h2 headings, want exactly one", page, count)
			}
			*cardCount++
		}
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		countLayoutHeadings(child, h1Count, cardCount, t, page)
	}
}

func countDescendantHeadings(node *html.Node, tag string) int {
	count := 0
	if node.Type == html.ElementNode && node.Data == tag {
		count++
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		count += countDescendantHeadings(child, tag)
	}
	return count
}

func findElement(node *html.Node, tag string) *html.Node {
	if node.Type == html.ElementNode && node.Data == tag {
		return node
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if found := findElement(child, tag); found != nil {
			return found
		}
	}
	return nil
}

func elementAttribute(node *html.Node, key string) string {
	for _, attr := range node.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

func findElementByID(node *html.Node, id string) *html.Node {
	if node.Type == html.ElementNode && elementAttribute(node, "id") == id {
		return node
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if found := findElementByID(child, id); found != nil {
			return found
		}
	}
	return nil
}

func findElementByClass(node *html.Node, class string) *html.Node {
	if node.Type == html.ElementNode && hasClass(node, class) {
		return node
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if found := findElementByClass(child, class); found != nil {
			return found
		}
	}
	return nil
}

func hasClass(node *html.Node, class string) bool {
	return strings.Contains(" "+elementAttribute(node, "class")+" ", " "+class+" ")
}

// testPageData builds the minimum PageData needed to render a layout page.
func testPageData() handler.PageData {
	return handler.PageData{
		Lang:           "en",
		Dir:            "ltr",
		Theme:          "dark",
		CurrentYear:    2024,
		ProjectName:    "ipgaze",
		Version:        "1.0.0",
		BuildDate:      "2024-01-01",
		RepoURL:        "https://github.com/apimgr/ipgaze",
		ContactChooser: true,
	}
}

// TestAccessibility is the automated accessibility check required by
// AI.md PART 30 Testing Requirements.
func TestAccessibility(t *testing.T) {
	log.SetOutput(io.Discard)

	t.Run("landing page", func(t *testing.T) {
		ts := httptest.NewServer(testServer().Handler())
		defer ts.Close()

		req, err := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept", "text/html")
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible browser)")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}

		assertAccessibleDocument(t, "index.tmpl", string(body))
		assertPageConformance(t, "index.tmpl", string(body))
	})

	t.Run("layout pages", func(t *testing.T) {
		render := NewPageRenderer("0.0.0-testcommit")
		if render == nil {
			t.Fatal("NewPageRenderer returned nil")
		}

		for _, page := range []string{"about.tmpl", "terms.tmpl", "help.tmpl", "help_mcp.tmpl", "contact.tmpl", "preferences_tokens.tmpl", "privacy.tmpl", "healthz.tmpl", "swagger.tmpl", "graphql.tmpl"} {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/server/"+strings.TrimSuffix(page, ".tmpl"), nil)
			var data any = testPageData()
			if page == "help.tmpl" {
				data = struct {
					handler.PageData
					HelpPages []handler.HubPage
				}{PageData: testPageData(), HelpPages: []handler.HubPage{{Path: "/server/help/mcp", Title: "MCP connection guide", Description: "Connect AI clients to IPGaze through the public MCP endpoint."}}}
			}
			if page == "help_mcp.tmpl" {
				data = struct {
					handler.PageData
					handler.MCPHelpResponse
				}{PageData: testPageData(), MCPHelpResponse: handler.MCPHelpResponse{URL: "https://example.com/api/v1/server/mcp"}}
			}
			if page == "preferences_tokens.tmpl" {
				data = handler.OwnerTokensPageData{PageData: testPageData()}
			}
			if page == "privacy.tmpl" {
				pageData := testPageData()
				pageData.CSRFToken = "test-csrf-token"
				pageData.Privacy = &config.PrivacyConfig{
					Data:      config.DataPolicy{StoredOnServer: true, Sold: true},
					Retention: config.RetentionPolicy{Period: "30 days", ExportAvailable: true, DeletionAvailable: true},
					Cookies: config.CookieCategories{
						Essential:   config.CookieCategory{Enabled: true, Description: "Required for site operation."},
						Preferences: config.CookieCategory{Enabled: true, Description: "Stores visitor preferences."},
						Analytics:   config.AnalyticsCookie{CookieCategory: config.CookieCategory{Enabled: true, Description: "Usage analytics."}},
					},
					ThirdParty: config.ThirdPartyConfig{Services: []config.ThirdPartyService{{Name: "Analytics", Purpose: "Measure usage", DataSent: "Aggregated events", PolicyURL: "https://example.com/privacy"}}},
					Content:    config.PrivacyContent{DataCollection: "Data collection details.", DataUsage: "Data usage details.", DataUsageIfSold: "Data usage details when data is sold.", DataSecurity: "Data security details."},
				}
				data = pageData
			}
			if page == "healthz.tmpl" {
				data = handler.HealthzPageData{PageData: testPageData(), AssetStamp: "1.0.0-testcommit"}
			}
			if page == "swagger.tmpl" || page == "graphql.tmpl" {
				pageData := testPageData()
				pageData.AssetStamp = "1.0.0-testcommit"
				pageData.SwaggerSpecURL = "https://example.com/api/v1/server/swagger"
				pageData.GraphQLEndpoint = "https://example.com/api/v1/server/graphql"
				data = pageData
			}
			if err := render(rec, req, page, data); err != nil {
				t.Fatalf("render %s: %v", page, err)
			}
			assertAccessibleDocument(t, page, rec.Body.String())
			if page != "preferences_tokens.tmpl" && page != "swagger.tmpl" && page != "healthz.tmpl" {
				assertLayoutStructure(t, page, rec.Body.String())
			}
			assertPageConformance(t, page, rec.Body.String())
			if page == "help_mcp.tmpl" {
				assertBreadcrumbConformance(t, page, rec.Body.String(), "/server/help")
			} else if page == "preferences_tokens.tmpl" {
				assertBreadcrumbConformance(t, page, rec.Body.String(), "/server/preferences")
			} else {
				assertBreadcrumbConformance(t, page, rec.Body.String(), "")
			}
		}

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/server/preferences", nil)
		prefs := handler.PreferencesPageData{
			PageData:              testPageData(),
			PreferencePages:       []handler.HubPage{{Path: "/server/preferences/sync", Title: "Sync preferences", Description: "Move guest preferences to another browser with an export link or code."}},
			PreferencesExportURL:  "https://example.com/server/preferences/sync/import?lang=en&theme=dark",
			PreferencesExportCode: "bGFuZz1lbiZ0aGVtZT1kYXJr",
			CancelURL:             "/",
		}
		prefs.RequestPath = "/server/preferences"
		if err := render(rec, req, "preferences.tmpl", prefs); err != nil {
			t.Fatalf("render preferences.tmpl: %v", err)
		}
		body := rec.Body.String()
		assertAccessibleDocument(t, "preferences.tmpl", body)
		assertPageConformance(t, "preferences.tmpl", body)
		if got := strings.Count(body, `method="POST"`); got != 1 {
			t.Errorf("preferences page POST forms = %d, want 1", got)
		}
		for _, required := range []string{`name="consent_form"`, `name="consent_preferences"`, `name="consent_analytics"`, `name="action" value="reset"`, `preferences-reset-popover`, `more-preferences`, `/server/preferences/sync`} {
			if !strings.Contains(body, required) {
				t.Errorf("preferences page missing %q", required)
			}
		}
		if strings.Count(body, `class="theme-toggle-form"`) != 1 || strings.Contains(body, `id="cookie-preferences-modal"`) {
			t.Error("preferences page must keep the single header theme form and omit the global consent dialog")
		}
		if strings.Contains(body, `name="code"`) || strings.Contains(body, `preferences-export-url`) {
			t.Error("preferences page contains sync controls")
		}

		syncRec := httptest.NewRecorder()
		syncReq := httptest.NewRequest(http.MethodGet, "/server/preferences/sync", nil)
		syncData := handler.PreferencesPageData{PageData: testPageData(), PreferencesExportURL: "https://example.com/server/preferences/sync/import?lang=en&theme=dark", PreferencesExportCode: "bGFuZz1lbiZ0aGVtZT1kYXJr"}
		syncData.RequestPath = "/server/preferences/sync"
		if err := render(syncRec, syncReq, "preferences_sync.tmpl", syncData); err != nil {
			t.Fatalf("render preferences_sync.tmpl: %v", err)
		}
		syncBody := syncRec.Body.String()
		assertAccessibleDocument(t, "preferences_sync.tmpl", syncBody)
		assertPageConformance(t, "preferences_sync.tmpl", syncBody)
		assertBreadcrumbConformance(t, "preferences_sync.tmpl", syncBody, "/server/preferences")
		if !strings.Contains(syncBody, `name="code"`) || !strings.Contains(syncBody, `preferences-export-url`) {
			t.Error("preference sync page is missing its export block or code import field")
		}
	})
}
