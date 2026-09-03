// Package main output renderers for the five formats AI.md PART 32 defines:
// table, json, yaml, plain and csv.
package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"gopkg.in/yaml.v3"

	"github.com/apimgr/ipgaze/src/client/api"
)

// recordField is one label/value pair of an IP lookup result.
type recordField struct {
	Key   string
	Label string
	Value string
}

// formatFloat renders a coordinate without trailing zeros.
func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// recordFields flattens an IPResponse into ordered label/value pairs, skipping
// unset values so a lookup without GeoIP data does not print empty rows.
func recordFields(r *api.IPResponse) []recordField {
	fields := []recordField{
		{"ip", "IP Address", r.IP},
	}
	if r.IPDecimal != 0 {
		fields = append(fields, recordField{"ip_decimal", "IP Decimal", strconv.FormatUint(r.IPDecimal, 10)})
	}
	if r.Hostname != "" {
		fields = append(fields, recordField{"hostname", "Hostname", r.Hostname})
	}
	if r.Country != "" {
		fields = append(fields, recordField{"country", "Country", r.Country})
	}
	if r.CountryISO != "" {
		fields = append(fields, recordField{"country_iso", "Country ISO", r.CountryISO})
	}
	if r.City != "" {
		fields = append(fields, recordField{"city", "City", r.City})
	}
	if r.RegionName != "" {
		fields = append(fields, recordField{"region_name", "Region", r.RegionName})
	}
	if r.RegionCode != "" {
		fields = append(fields, recordField{"region_code", "Region Code", r.RegionCode})
	}
	if r.PostalCode != "" {
		fields = append(fields, recordField{"zip_code", "Postal Code", r.PostalCode})
	}
	if r.Latitude != 0 || r.Longitude != 0 {
		fields = append(fields,
			recordField{"latitude", "Latitude", formatFloat(r.Latitude)},
			recordField{"longitude", "Longitude", formatFloat(r.Longitude)},
		)
	}
	if r.Timezone != "" {
		fields = append(fields, recordField{"time_zone", "Time Zone", r.Timezone})
	}
	if r.ASN != "" {
		fields = append(fields, recordField{"asn", "ASN", r.ASN})
	}
	if r.ASNOrg != "" {
		fields = append(fields, recordField{"asn_org", "ASN Org", r.ASNOrg})
	}
	return fields
}

// renderRecord writes an IP lookup result in the requested format. format must
// already have been validated against setup.OutputFormats.
func renderRecord(w io.Writer, format string, r *api.IPResponse) error {
	switch format {
	case "json":
		return renderJSON(w, r)
	case "yaml":
		return renderYAML(w, r)
	case "csv":
		return renderCSV(w, r)
	case "plain":
		return renderPlain(w, r)
	case "table":
		return renderTable(w, r)
	}
	return fmt.Errorf("unsupported output format: %s", format)
}

// renderJSON writes the record as indented JSON.
func renderJSON(w io.Writer, r *api.IPResponse) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// renderYAML writes the record as YAML keyed by the same names JSON uses.
func renderYAML(w io.Writer, r *api.IPResponse) error {
	doc := make(map[string]string, len(recordFields(r)))
	for _, f := range recordFields(r) {
		doc[f.Key] = f.Value
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// renderCSV writes a two-line CSV: a header row of field names and one row of
// values, which is what a single-record lookup maps to.
func renderCSV(w io.Writer, r *api.IPResponse) error {
	fields := recordFields(r)
	header := make([]string, 0, len(fields))
	values := make([]string, 0, len(fields))
	for _, f := range fields {
		header = append(header, f.Key)
		values = append(values, f.Value)
	}

	writer := csv.NewWriter(w)
	if err := writer.Write(header); err != nil {
		return err
	}
	if err := writer.Write(values); err != nil {
		return err
	}
	writer.Flush()
	return writer.Error()
}

// renderPlain writes aligned "Label: value" lines with no decoration, the
// format meant for grep/awk pipelines.
func renderPlain(w io.Writer, r *api.IPResponse) error {
	fields := recordFields(r)
	width := 0
	for _, f := range fields {
		if len(f.Label) > width {
			width = len(f.Label)
		}
	}
	for _, f := range fields {
		if _, err := fmt.Fprintf(w, "%-*s  %s\n", width+1, f.Label+":", f.Value); err != nil {
			return err
		}
	}
	return nil
}

// printFormatted writes the plain human-readable block to stdout. It is the
// fallback rendering used when the TUI cannot start.
func printFormatted(r *api.IPResponse) {
	_ = renderPlain(os.Stdout, r)
}

// renderTable writes the box-drawn table AI.md PART 32 shows for --output table.
func renderTable(w io.Writer, r *api.IPResponse) error {
	t := table.New().
		Border(lipgloss.NormalBorder()).
		Headers("FIELD", "VALUE")
	for _, f := range recordFields(r) {
		t.Row(f.Label, f.Value)
	}
	_, err := fmt.Fprintln(w, t.Render())
	return err
}
