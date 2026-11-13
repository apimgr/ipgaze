//go:build gui && (linux || darwin || windows)

package gui

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/apimgr/ipgaze/src/client/api"
	"github.com/apimgr/ipgaze/src/common/display"
	"github.com/apimgr/ipgaze/src/common/i18n"
	"github.com/gogpu/gg"
	_ "github.com/gogpu/gg/gpu"
	"github.com/gogpu/gg/integration/ggcanvas"
	"github.com/gogpu/gogpu"
	"github.com/gogpu/ui/app"
	"github.com/gogpu/ui/core/button"
	"github.com/gogpu/ui/core/textfield"
	"github.com/gogpu/ui/primitives"
	"github.com/gogpu/ui/render"
	"github.com/gogpu/ui/state"
	"github.com/gogpu/ui/theme/material3"
	"github.com/gogpu/ui/widget"
)

// IsGUIAvailable reports whether this binary supports GUI and the current
// invocation has a local display rather than an SSH or Mosh session.
func IsGUIAvailable() bool {
	env := display.DetectDisplayEnv()
	return env.HasDisplay && !env.IsSSH && !env.IsMosh
}

// LaunchGUI opens a native IP lookup window backed by the project's API client.
func LaunchGUI(client *api.APIClient, locale, configuredTheme string) error {
	window := gogpu.NewApp(gogpu.DefaultConfig().WithTitle(translate(locale, "gui.title")).WithSize(800, 640))
	mode := strings.ToLower(configuredTheme)
	if mode != "light" && mode != "dark" && mode != "auto" && mode != "system" {
		mode = "dark"
	}
	if mode == "system" {
		mode = "auto"
	}
	ui := app.New(
		app.WithWindowProvider(window),
		app.WithPlatformProvider(window),
		app.WithEventSource(window.EventSource()),
	)

	inputValue := ""
	lastDark := mode == "dark" || (mode == "auto" && window.DarkMode())
	status := state.NewSignal(translate(locale, "gui.ready"))
	result := state.NewSignal(translate(locale, "gui.empty"))
	field := textfield.New(
		textfield.Placeholder(translate(locale, "gui.ip_placeholder")),
		textfield.A11yLabel(translate(locale, "gui.lookup_label")),
		textfield.Validation(func(value string) string {
			if value != "" && net.ParseIP(strings.TrimSpace(value)) == nil {
				return translate(locale, "gui.invalid_ip")
			}
			return ""
		}),
		textfield.OnChange(func(value string) { inputValue = strings.TrimSpace(value) }),
	)
	var background [4]float64
	var renderWindow func()
	setTheme := func(next string) {
		mode = next
		lastDark = mode == "dark" || (mode == "auto" && window.DarkMode())
		renderWindow()
	}
	lookup := func(ownIP bool) {
		ip := inputValue
		if !ownIP {
			if net.ParseIP(ip) == nil {
				status.Set(translate(locale, "gui.invalid_ip"))
				result.Set(translate(locale, "gui.validation_hint"))
				return
			}
		}
		status.Set(translate(locale, "gui.loading"))
		result.Set(translate(locale, "gui.loading_detail"))
		go func() {
			var response *api.IPResponse
			var err error
			if ownIP {
				response, err = client.GetMyIPJSON(context.Background())
			} else {
				response, err = client.GetIPJSON(context.Background(), ip)
			}
			if err != nil {
				status.Set(translate(locale, "gui.failed"))
				result.Set(fmt.Sprintf("%s\n%s", translate(locale, "gui.error_detail"), err.Error()))
				return
			}
			status.Set(translate(locale, "gui.success"))
			result.Set(formatResponse(locale, response))
		}()
	}
	renderWindow = func() {
		isDark := mode == "dark" || (mode == "auto" && window.DarkMode())
		m3 := material3.NewDark(widget.Hex(0x6750A4))
		if !isDark {
			m3 = material3.New(widget.Hex(0x6750A4))
		}
		red, green, blue, alpha := m3.Colors.Background.RGBA8()
		background = [4]float64{float64(red) / 255, float64(green) / 255, float64(blue) / 255, float64(alpha) / 255}
		root := primitives.Box(
			primitives.Text(translate(locale, "gui.title")).FontSize(28).Bold(),
			primitives.Text(translate(locale, "gui.subtitle")).FontSize(15),
			primitives.Text(translate(locale, "gui.lookup_label")).FontSize(15).Bold(),
			field,
			primitives.HBox(
				button.New(button.TextOpt(translate(locale, "gui.lookup_button")), button.OnClick(func() { lookup(false) }), button.PainterOpt(material3.ButtonPainter{Theme: m3})),
				button.New(button.TextOpt(translate(locale, "gui.my_ip_button")), button.OnClick(func() { lookup(true) }), button.PainterOpt(material3.ButtonPainter{Theme: m3})),
				button.New(button.TextOpt(themeLabel(locale, mode)), button.OnClick(func() {
					switch mode {
					case "dark":
						setTheme("light")
					case "light":
						setTheme("auto")
					default:
						setTheme("dark")
					}
				}), button.VariantOpt(button.Outlined), button.PainterOpt(material3.ButtonPainter{Theme: m3})),
			).Gap(12),
			primitives.Text("").ContentSignal(status).FontSize(14).Bold(),
			primitives.Text("").ContentSignal(result).FontSize(15).FontFamily("monospace"),
			primitives.Text(translate(locale, "gui.keyboard_hint")).FontSize(12),
		).Padding(32).Gap(16)
		ui.SetRoot(root)
	}
	renderWindow()

	var canvas *ggcanvas.Canvas
	window.OnDraw(func(dc *gogpu.Context) {
		if mode == "auto" && lastDark != window.DarkMode() {
			lastDark = window.DarkMode()
			renderWindow()
		}
		width, height := dc.Width(), dc.Height()
		if width <= 0 || height <= 0 {
			return
		}
		if canvas == nil {
			provider := window.GPUContextProvider()
			if provider == nil {
				return
			}
			var err error
			canvas, err = ggcanvas.New(provider, width, height)
			if err != nil {
				log.Printf("gui: initialize canvas: %v", err)
				return
			}
		}
		ui.Frame()
		cw, ch := canvas.Size()
		if cw != width || ch != height {
			if err := canvas.Resize(width, height); err != nil {
				log.Printf("gui: resize canvas: %v", err)
			}
			cw, ch = canvas.Size()
		}
		canvas.Draw(func(cc *gg.Context) {
			cc.SetRGBA(background[0], background[1], background[2], background[3])
			cc.DrawRectangle(0, 0, float64(cw), float64(ch))
			cc.Fill()
			ui.Window().DrawTo(render.NewCanvas(cc, cw, ch))
		})
		surface := dc.RenderTarget().SurfaceView()
		surfaceWidth, surfaceHeight := dc.SurfaceSize()
		if err := canvas.RenderDirect(surface, surfaceWidth, surfaceHeight); err != nil {
			log.Printf("gui: render: %v", err)
		}
	})
	window.OnClose(func() { gg.CloseAccelerator() })
	return window.Run()
}

// LaunchSetupWizard presents the first-run connection form. The caller saves
// the returned values only after the user confirms a successful connection.
func LaunchSetupWizard(locale, _ string, defaultServer string) (string, string, bool, bool, error) {
	window := gogpu.NewApp(gogpu.DefaultConfig().WithTitle(translate(locale, "gui.setup_title")).WithSize(680, 560))
	dark := window.DarkMode()
	theme := material3.NewDark(widget.Hex(0x6750A4))
	if !dark {
		theme = material3.New(widget.Hex(0x6750A4))
	}
	background := theme.Colors.Background
	ui := app.New(app.WithWindowProvider(window), app.WithPlatformProvider(window), app.WithEventSource(window.EventSource()))
	server, token := defaultServer, ""
	saveConfig, confirmed := true, false
	var setupMu sync.Mutex
	status := state.NewSignal(translate(locale, "gui.setup_intro"))
	serverField := textfield.New(
		textfield.Placeholder(translate(locale, "gui.server_placeholder")),
		textfield.A11yLabel(translate(locale, "gui.server_label")),
		textfield.Validation(func(value string) string {
			if value != "" && !validServerURL(normalizeServerURL(value)) {
				return translate(locale, "gui.invalid_server")
			}
			return ""
		}),
		textfield.OnChange(func(value string) {
			setupMu.Lock()
			server, confirmed = strings.TrimSpace(value), false
			setupMu.Unlock()
			status.Set(translate(locale, "gui.setup_intro"))
		}),
	)
	tokenField := textfield.New(
		textfield.Placeholder(translate(locale, "gui.token_placeholder")),
		textfield.A11yLabel(translate(locale, "gui.token_label")),
		textfield.InputTypeOpt(textfield.TypePassword),
		textfield.OnChange(func(value string) {
			setupMu.Lock()
			token, confirmed = value, false
			setupMu.Unlock()
			status.Set(translate(locale, "gui.setup_intro"))
		}),
	)
	var renderForm func()
	renderForm = func() {
		ui.SetRoot(primitives.Box(
			primitives.Text(translate(locale, "gui.setup_title")).FontSize(26).Bold(),
			primitives.Text("").ContentSignal(status).FontSize(15),
			primitives.Text(translate(locale, "gui.server_label")).FontSize(15).Bold(), serverField,
			primitives.Text(translate(locale, "gui.token_label")).FontSize(15).Bold(), tokenField,
			button.New(button.TextOpt(saveLabel(locale, saveConfig)), button.OnClick(func() { saveConfig = !saveConfig; renderForm() }), button.VariantOpt(button.Outlined), button.PainterOpt(material3.ButtonPainter{Theme: theme})),
			primitives.HBox(
				button.New(button.TextOpt(translate(locale, "gui.test_connection")), button.OnClick(func() {
					setupMu.Lock()
					base, tokenSnapshot := normalizeServerURL(server), token
					confirmed = false
					setupMu.Unlock()
					if !validServerURL(base) {
						status.Set(translate(locale, "gui.invalid_server"))
						return
					}
					status.Set(translate(locale, "gui.testing"))
					go func() {
						req, err := http.NewRequest(http.MethodGet, base+"/api/v1/server/healthz", nil)
						if err == nil {
							req.Header.Set("Accept", "application/json")
							if tokenSnapshot != "" {
								req.Header.Set("Authorization", "Bearer "+tokenSnapshot)
							}
							response, requestErr := (&http.Client{Timeout: 10 * time.Second}).Do(req)
							if requestErr != nil {
								err = requestErr
							} else {
								defer response.Body.Close()
								if response.StatusCode < 200 || response.StatusCode >= 300 {
									err = fmt.Errorf("%s", i18n.TranslateFormat(locale, "gui.http_error", "status", fmt.Sprint(response.StatusCode)))
								}
							}
						}
						if err != nil {
							status.Set(fmt.Sprintf("%s: %v", translate(locale, "gui.failed"), err))
							return
						}
						setupMu.Lock()
						stillCurrent := normalizeServerURL(server) == base && token == tokenSnapshot
						if stillCurrent {
							confirmed = true
						}
						setupMu.Unlock()
						if stillCurrent {
							status.Set(translate(locale, "gui.connected"))
						} else {
							status.Set(translate(locale, "gui.setup_intro"))
						}
					}()
				}), button.PainterOpt(material3.ButtonPainter{Theme: theme})),
				button.New(button.TextOpt(translate(locale, "gui.continue")), button.DisabledFn(func() bool {
					setupMu.Lock()
					defer setupMu.Unlock()
					return !confirmed
				}), button.OnClick(func() {
					setupMu.Lock()
					canContinue := confirmed
					setupMu.Unlock()
					if canContinue {
						window.Close()
					}
				}), button.PainterOpt(material3.ButtonPainter{Theme: theme})),
				button.New(button.TextOpt(translate(locale, "gui.cancel")), button.OnClick(func() {
					setupMu.Lock()
					confirmed = false
					setupMu.Unlock()
					window.Close()
				}), button.VariantOpt(button.Outlined), button.PainterOpt(material3.ButtonPainter{Theme: theme})),
			).Gap(12),
		).Padding(32).Gap(16))
	}
	renderForm()
	var canvas *ggcanvas.Canvas
	window.OnDraw(func(dc *gogpu.Context) {
		if dark != window.DarkMode() {
			dark = window.DarkMode()
			theme = material3.NewDark(widget.Hex(0x6750A4))
			if !dark {
				theme = material3.New(widget.Hex(0x6750A4))
			}
			background = theme.Colors.Background
			renderForm()
		}
		w, h := dc.Width(), dc.Height()
		if w <= 0 || h <= 0 {
			return
		}
		if canvas == nil {
			provider := window.GPUContextProvider()
			if provider == nil {
				return
			}
			var err error
			canvas, err = ggcanvas.New(provider, w, h)
			if err != nil {
				log.Printf("gui setup: initialize canvas: %v", err)
				return
			}
		}
		ui.Frame()
		cw, ch := canvas.Size()
		if cw != w || ch != h {
			if err := canvas.Resize(w, h); err != nil {
				log.Printf("gui setup: resize canvas: %v", err)
			}
			cw, ch = canvas.Size()
		}
		canvas.Draw(func(cc *gg.Context) {
			red, green, blue, alpha := background.RGBA8()
			cc.SetRGBA(float64(red)/255, float64(green)/255, float64(blue)/255, float64(alpha)/255)
			cc.DrawRectangle(0, 0, float64(cw), float64(ch))
			cc.Fill()
			ui.Window().DrawTo(render.NewCanvas(cc, cw, ch))
		})
		surface := dc.RenderTarget().SurfaceView()
		surfaceWidth, surfaceHeight := dc.SurfaceSize()
		if err := canvas.RenderDirect(surface, surfaceWidth, surfaceHeight); err != nil {
			log.Printf("gui setup: render: %v", err)
		}
	})
	window.OnClose(func() { gg.CloseAccelerator() })
	err := window.Run()
	setupMu.Lock()
	serverResult, tokenResult, confirmedResult := normalizeServerURL(server), token, confirmed
	setupMu.Unlock()
	return serverResult, tokenResult, saveConfig, confirmedResult, err
}

func saveLabel(locale string, enabled bool) string {
	key := "gui.save_disabled"
	if enabled {
		key = "gui.save_enabled"
	}
	return translate(locale, key)
}

func normalizeServerURL(value string) string {
	value = strings.TrimSpace(value)
	if value != "" && !strings.HasPrefix(value, "http://") && !strings.HasPrefix(value, "https://") {
		value = "https://" + value
	}
	return strings.TrimSuffix(value, "/")
}

func validServerURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
}

func translate(locale, key string) string { return i18n.Translate(locale, key) }

func themeLabel(locale, mode string) string {
	key := "gui.theme_auto"
	if mode == "dark" {
		key = "gui.theme_dark"
	} else if mode == "light" {
		key = "gui.theme_light"
	}
	return translate(locale, key)
}

func formatResponse(locale string, response *api.IPResponse) string {
	rows := []string{
		translate(locale, "gui.field_ip") + ": " + response.IP,
		translate(locale, "gui.field_country") + ": " + response.Country,
		translate(locale, "gui.field_city") + ": " + response.City,
		translate(locale, "gui.field_region") + ": " + response.RegionName,
		translate(locale, "gui.field_postal") + ": " + response.PostalCode,
		translate(locale, "gui.field_timezone") + ": " + response.Timezone,
		translate(locale, "gui.field_asn") + ": " + response.ASN + " " + response.ASNOrg,
		translate(locale, "gui.field_hostname") + ": " + response.Hostname,
		translate(locale, "gui.field_coordinates") + ": " + fmt.Sprintf("%g, %g", response.Latitude, response.Longitude),
	}
	rows = appendOptionalFlag(locale, rows, "gui.field_country_eu", response.CountryEU)
	rows = appendOptionalFlag(locale, rows, "gui.field_vpn", response.IsVPN)
	rows = appendOptionalFlag(locale, rows, "gui.field_proxy", response.IsProxy)
	rows = appendOptionalFlag(locale, rows, "gui.field_tor", response.IsTor)
	rows = appendOptionalFlag(locale, rows, "gui.field_tor_hidden_service", response.IsTorHiddenService)
	return strings.Join(rows, "\n")
}

func appendOptionalFlag(locale string, rows []string, label string, value *bool) []string {
	if value == nil {
		return rows
	}
	status := translate(locale, "gui.no")
	if *value {
		status = translate(locale, "gui.yes")
	}
	return append(rows, translate(locale, label)+": "+status)
}
