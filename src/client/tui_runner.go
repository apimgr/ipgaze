package main

import (
	"context"

	"github.com/apimgr/ipgaze/src/client/api"
	cliout "github.com/apimgr/ipgaze/src/client/cli"
	"github.com/apimgr/ipgaze/src/client/setup"
	"github.com/apimgr/ipgaze/src/client/tui"
	tea "github.com/charmbracelet/bubbletea"
)

// runTUI launches the bubbletea TUI, fetching the caller's IP in the background.
// Falls back to formatted CLI output if the TUI fails to start.
func runTUI(ctx context.Context, client *api.APIClient, out *cliout.Output, cfg *setup.CLIConfig) {
	m := tui.NewModel()

	// Fetch IP asynchronously and send result into the TUI.
	fetchCmd := func() tea.Msg {
		resp, err := client.GetMyIPJSON(ctx)
		if err != nil {
			return tui.IPErrorMsg{Err: err}
		}
		return tui.IPResultMsg{
			Data: &tui.IPData{
				IP:         resp.IP,
				Hostname:   resp.Hostname,
				Country:    resp.Country,
				CountryISO: resp.CountryISO,
				City:       resp.City,
				RegionName: resp.RegionName,
				RegionCode: resp.RegionCode,
				ASN:        resp.ASN,
				ASNOrg:     resp.ASNOrg,
				Latitude:   resp.Latitude,
				Longitude:  resp.Longitude,
				Timezone:   resp.Timezone,
				PostalCode: resp.PostalCode,
			},
		}
	}

	// Attach the fetch command so the TUI starts it alongside the spinner.
	_ = m.Init()

	if err := tui.RunWithCmd(m, fetchCmd); err != nil {
		// TUI failed — fall back to formatted output.
		resp, apiErr := client.GetMyIPJSON(ctx)
		if apiErr != nil {
			out.PrintError("%v", apiErr)
			return
		}
		printFormatted(resp)
	}
}
