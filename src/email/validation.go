package email

import (
	"fmt"
	"regexp"
	"strings"
)

var emailVariablePattern = regexp.MustCompile(`\{([^{}]+)\}`)

var supportedEmailVariables = map[string]struct{}{
	"action": {}, "app_name": {}, "app_url": {}, "channel": {}, "current_version": {},
	"days": {}, "days_until_expiry": {}, "details": {}, "domain": {}, "error": {},
	"event": {}, "expiry": {}, "expiry_date": {}, "filename": {}, "fqdn": {}, "free": {},
	"from_line": {}, "heading": {}, "hostname": {}, "intro": {}, "ip": {}, "i2p_address": {},
	"i2p_url": {}, "label_channel": {}, "label_current_version": {}, "label_days_remaining": {},
	"label_days_until_expiry": {}, "label_domain": {}, "label_error": {}, "label_event": {}, "label_free_space": {},
	"label_expires": {}, "label_filename": {}, "label_ip": {}, "label_new_expiry": {},
	"label_new_version": {}, "label_next_retry": {}, "label_next_run": {}, "label_previous_version": {},
	"label_mode": {}, "label_path": {}, "label_reason": {}, "label_size": {}, "label_task": {}, "label_threshold": {}, "label_time": {}, "label_used_percent": {}, "message": {}, "mode": {}, "new_version": {},
	"next_retry": {}, "next_run": {}, "onion_address": {}, "onion_url": {}, "path": {}, "previous_version": {},
	"reason": {}, "size": {}, "since": {}, "staged_version": {}, "subject": {}, "task": {}, "task_name": {},
	"threshold_percent": {}, "time": {}, "timestamp": {}, "used_percent": {}, "valid_until": {}, "version": {}, "year": {},
}

// TemplatePreview is a rendered, validated template for the maintenance CLI.
type TemplatePreview struct {
	Name    string
	Subject string
	Body    string
}

// ValidateTemplate checks the subject, body, syntax, and variables in a template.
func ValidateTemplate(t *Template) []error {
	if t == nil {
		return []error{fmt.Errorf("template is nil")}
	}
	var errs []error
	if strings.TrimSpace(t.Subject) == "" {
		errs = append(errs, fmt.Errorf("%s", "Subject cannot be empty"))
	}
	if strings.TrimSpace(t.Body) == "" {
		errs = append(errs, fmt.Errorf("%s", "Body cannot be empty"))
	}
	for partIndex, part := range []string{t.Subject, t.Body} {
		lines := strings.Split(part, "\n")
		for lineNumber, line := range lines {
			if partIndex == 1 {
				lineNumber += 2
			}
			if strings.Count(line, "{") != strings.Count(line, "}") {
				errs = append(errs, fmt.Errorf("%s", fmt.Sprintf("Invalid template syntax at line %d", lineNumber+1)))
				continue
			}
			for _, match := range emailVariablePattern.FindAllStringSubmatch(line, -1) {
				name := match[1]
				if _, ok := supportedEmailVariables[name]; ok {
					continue
				}
				if name == "foo" {
					errs = append(errs, fmt.Errorf("%s", fmt.Sprintf("Unknown variable: {%s}. Did you mean {fqdn}?", name)))
				} else {
					errs = append(errs, fmt.Errorf("%s", fmt.Sprintf("Unknown variable: {%s}", name)))
				}
			}
		}
	}
	return errs
}

// PreviewTemplates validates all templates and renders them with sample values.
// Invalid disk overrides are reported and previewed using their embedded default.
func (m *EmailManager) PreviewTemplates(vars map[string]string, lang string) ([]TemplatePreview, []error) {
	names, err := DefaultTemplateNames()
	if err != nil {
		return nil, []error{err}
	}
	previews := make([]TemplatePreview, 0, len(names))
	var errs []error
	for _, name := range names {
		template, loadErr := m.loadTemplateForPreview(name)
		if loadErr != nil {
			errs = append(errs, loadErr)
			template, loadErr = loadEmbeddedTemplate(name)
		}
		if loadErr != nil {
			errs = append(errs, loadErr)
			continue
		}
		for _, validationErr := range ValidateTemplate(template) {
			errs = append(errs, fmt.Errorf("%s: %w", name, validationErr))
		}
		subject, body := template.Render(localizedTemplateVars(name, lang, vars))
		previews = append(previews, TemplatePreview{Name: name, Subject: subject, Body: body})
	}
	return previews, errs
}
