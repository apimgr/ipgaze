package config

import (
	"fmt"
	"html"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func migrateLegacyKeys(path string, content []byte) []byte {
	var document yaml.Node
	if err := yaml.Unmarshal(content, &document); err != nil || len(document.Content) == 0 || document.Content[0].Kind != yaml.MappingNode {
		return content
	}
	root := document.Content[0]
	changed := false
	move := func(oldPath, newPath string) { changed = moveLegacyNode(root, oldPath, newPath) || changed }
	remove := func(keyPath string) { changed = removeLegacyNode(root, keyPath) || changed }
	changed = migrateLegacyDatabase(root) || changed
	move("server.logging", "server.logs")
	move("server.logs.access_format", "server.logs.access.format")
	move("server.schedule", "server.scheduler")
	remove("server.scheduler.enabled")
	if node := findConfigNode(root, "server.scheduler.geoip_update"); node != nil && node.Kind == yaml.ScalarNode {
		remove("server.scheduler.geoip_update")
	}
	move("server.web.cookie_consent.message", "server.privacy.consent.message")
	move("server.web.cookie_consent.policy_url", "server.privacy.consent.policy.url")
	remove("server.web.cookie_consent.enabled")
	move("server.web", "web")
	move("server.security_headers.hsts", "web.hsts.enabled")
	move("server.security_headers.hsts_max_age", "web.hsts.max_age_seconds")
	remove("server.security_headers")
	move("server.security.hsts", "web.hsts")
	move("server.security.nel", "web.headers.nel")
	move("server.security.headers.clear_site_data", "web.headers.clear_site_data")
	remove("server.security.headers")
	move("server.security.csrf", "server.csrf")
	move("web.csrf", "server.csrf")
	move("server.title", "server.branding.title")
	move("server.description", "server.branding.description")
	move("server.branding.logo_url", "server.branding.logo")
	move("server.branding.favicon_url", "server.branding.favicon")
	move("server.branding.primary_color", "web.ui.accent")
	changed = moveLegacyContent(root, "server.branding.footer_text", "server.branding.content.footer", "html", true) || changed
	move("web.favicon_url", "server.branding.favicon")
	move("web.ui.favicon", "server.branding.favicon")
	move("web.ui.logo", "server.branding.logo")
	changed = moveLegacyContent(root, "web.footer.custom_html", "server.branding.content.footer", "html", false) || changed
	for _, page := range []string{"about", "privacy", "terms"} {
		changed = moveLegacyContent(root, "server.pages."+page+".content", "server.branding.content."+page, "md", false) || changed
	}
	move("server.admin.email", "server.contact.admin.email")
	move("server.admin.path", "server.admin_path")
	for _, key := range []string{"server.admin.password", "server.admin.token", "server.admin.username", "server.admin.two_factor"} {
		remove(key)
	}
	if httpsPort := findConfigNode(root, "server.https_port"); httpsPort != nil {
		var value int
		if err := httpsPort.Decode(&value); err == nil && value > 0 {
			port := findConfigNode(root, "server.port")
			current := ""
			if port != nil {
				current = port.Value
			}
			setConfigNode(root, "server.port", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: fmt.Sprintf("%s,%d", current, value)})
		}
		remove("server.https_port")
	}
	for _, mapping := range [][2]string{
		{"server.ssl.dns01.provider", "server.ssl.letsencrypt.dns_provider"},
		{"server.ssl.dns01.credentials", "server.ssl.letsencrypt.dns_credentials"},
		{"server.ssl.dns01.credentials_encrypted", "server.ssl.letsencrypt.dns_credentials"},
		{"server.ssl.letsencrypt.provider", "server.ssl.letsencrypt.dns_provider"},
		{"server.ssl.letsencrypt.credentials_encrypted", "server.ssl.letsencrypt.dns_credentials"},
	} {
		move(mapping[0], mapping[1])
	}
	for _, key := range []string{
		"server.ssl.letsencrypt.validated_at", "server.ssl.letsencrypt.domain", "server.ssl.letsencrypt.domains",
		"server.ssl.dns01.validated_at", "server.ssl.dns01.domain", "server.ssl.dns01.domains",
	} {
		remove(key)
	}
	changed = pruneSchedulerTaskKeys(root) || changed
	for _, key := range []string{
		"server.branding.theme_color", "server.branding.source_code_url", "server.privacy.content",
		"server.mcp", "server.rate_limit.enabled", "server.rate_limit.requests", "server.rate_limit.window",
		"server.maintenance_mode", "server.i18n.auto_detect", "server.i18n.rtl_languages",
		"server.i18n.show_selector", "server.i18n.translations_dir", "server.geoip.dir",
		"server.geoip.databases", "server.geoip.country_mode", "server.database.sqlite",
		"server.metrics.endpoint", "server.notifications.email_enabled", "server.notifications.webhook_enabled",
		"server.secret_key", "web.permissions_policy", "web.honor_dnt", "web.robots.ai_bots",
	} {
		remove(key)
	}
	if changed {
		pruneEmptyConfigMaps(root)
		migrated, err := yaml.Marshal(&document)
		if err == nil {
			if err := backupAndWriteConfig(path, migrated); err != nil {
				log.Printf("config: legacy key migration for %s could not be persisted: %v", path, err)
			}
			return migrated
		}
		log.Printf("config: legacy key migration for %s could not be encoded: %v", path, err)
	}
	return content
}

func migrateLegacyDatabase(root *yaml.Node) bool {
	legacy := findConfigNode(root, "database")
	if legacy == nil || legacy.Kind != yaml.MappingNode {
		return false
	}
	migrated := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for index := 0; index+1 < len(legacy.Content); index += 2 {
		key, value := legacy.Content[index], legacy.Content[index+1]
		if key.Value == "primary" && value.Kind == yaml.MappingNode {
			for child := 0; child+1 < len(value.Content); child += 2 {
				migrated.Content = append(migrated.Content, cloneYAMLNode(value.Content[child]), cloneYAMLNode(value.Content[child+1]))
			}
			continue
		}
		migratedKey := cloneYAMLNode(key)
		if key.Value == "type" {
			migratedKey.Value = "driver"
		}
		migrated.Content = append(migrated.Content, migratedKey, cloneYAMLNode(value))
	}
	destination := findConfigNode(root, "server.database")
	if destination == nil {
		setConfigNode(root, "server.database", migrated)
	} else if destination.Kind == yaml.MappingNode {
		mergeMissingConfigNodes(destination, migrated)
	}
	removeLegacyNode(root, "database")
	return true
}

func pruneSchedulerTaskKeys(root *yaml.Node) bool {
	tasks := findConfigNode(root, "server.scheduler.tasks")
	if tasks == nil || tasks.Kind != yaml.MappingNode {
		return false
	}
	changed := false
	for i := 0; i+1 < len(tasks.Content); i += 2 {
		name, task := tasks.Content[i].Value, tasks.Content[i+1]
		if task.Kind != yaml.MappingNode {
			tasks.Content = append(tasks.Content[:i], tasks.Content[i+2:]...)
			changed = true
			i -= 2
			continue
		}
		for j := len(task.Content) - 2; j >= 0; j -= 2 {
			key := task.Content[j].Value
			allowed := key == "enabled" || key == "schedule" || key == "retry_on_fail" || key == "retry_delay"
			if key == "retention" && (name == "backup" || strings.HasPrefix(name, "backup_")) {
				allowed = true
			}
			if !allowed {
				task.Content = append(task.Content[:j], task.Content[j+2:]...)
				changed = true
			}
		}
		if isDefaultSchedulerTask(name, task) {
			tasks.Content = append(tasks.Content[:i], tasks.Content[i+2:]...)
			changed = true
			i -= 2
		}
	}
	return changed
}

func isDefaultSchedulerTask(name string, task *yaml.Node) bool {
	defaults := map[string]map[string]string{
		"geoip_update":     {"enabled": "true", "schedule": "0 3 * * 0", "retry_on_fail": "true", "retry_delay": "1h"},
		"blocklist_update": {"enabled": "true", "schedule": "0 4 * * *", "retry_on_fail": "true", "retry_delay": "1h"},
		"cve_update":       {"enabled": "true", "schedule": "0 5 * * *", "retry_on_fail": "true", "retry_delay": "1h"},
		"log_rotation":     {"enabled": "true", "schedule": "0 0 * * *"},
		"token_cleanup":    {"enabled": "true", "schedule": "*/15 * * * *"},
		"backup":           {"enabled": "true", "schedule": "0 2 * * *", "retention": "5"},
		"ssl_renewal":      {"enabled": "true", "schedule": "0 3 * * *"},
		"health_check":     {"enabled": "true", "schedule": "*/5 * * * *"},
		"tor_health":       {"enabled": "true", "schedule": "*/10 * * * *"},
	}
	known, ok := defaults[name]
	if !ok {
		return false
	}
	for i := 0; i+1 < len(task.Content); i += 2 {
		key, value := task.Content[i].Value, task.Content[i+1]
		if known[key] == "" || value.Value != known[key] {
			return false
		}
	}
	return true
}

func pruneEmptyConfigMaps(node *yaml.Node) {
	if node.Kind != yaml.MappingNode {
		return
	}
	for i := len(node.Content) - 2; i >= 0; i -= 2 {
		value := node.Content[i+1]
		pruneEmptyConfigMaps(value)
		if value.Kind == yaml.MappingNode && len(value.Content) == 0 {
			node.Content = append(node.Content[:i], node.Content[i+2:]...)
		}
	}
}

func moveLegacyNode(root *yaml.Node, oldPath, newPath string) bool {
	oldNode := findConfigNode(root, oldPath)
	if oldNode == nil {
		return false
	}
	newNode := findConfigNode(root, newPath)
	if newNode == nil {
		setConfigNode(root, newPath, cloneYAMLNode(oldNode))
	} else if oldNode.Kind == yaml.MappingNode && newNode.Kind == yaml.MappingNode {
		mergeMissingConfigNodes(newNode, oldNode)
	}
	removeLegacyNode(root, oldPath)
	return true
}

func moveLegacyContent(root *yaml.Node, oldPath, newPath, format string, escape bool) bool {
	oldNode := findConfigNode(root, oldPath)
	if oldNode == nil {
		return false
	}
	if findConfigNode(root, newPath) == nil {
		content := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "format"}, {Kind: yaml.ScalarNode, Tag: "!!str", Value: format},
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "body"}, cloneYAMLNode(oldNode),
		}}
		if format == "html" && oldNode.Kind == yaml.ScalarNode {
			content = legacyFooterHTML(oldNode, escape)
		}
		setConfigNode(root, newPath, content)
	}
	removeLegacyNode(root, oldPath)
	return true
}

func mergeMissingConfigNodes(dst, src *yaml.Node) {
	if dst.Kind == yaml.SequenceNode && src.Kind == yaml.SequenceNode {
		for index, value := range src.Content {
			if index >= len(dst.Content) {
				dst.Content = append(dst.Content, cloneYAMLNode(value))
			} else if dst.Content[index].Kind == yaml.MappingNode && value.Kind == yaml.MappingNode {
				mergeMissingConfigNodes(dst.Content[index], value)
			}
		}
		return
	}
	if dst.Kind != yaml.MappingNode || src.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(src.Content); i += 2 {
		key, value := src.Content[i], src.Content[i+1]
		existing := findConfigNode(dst, key.Value)
		if existing == nil {
			dst.Content = append(dst.Content, cloneYAMLNode(key), cloneYAMLNode(value))
		} else if existing.Kind == yaml.MappingNode && value.Kind == yaml.MappingNode {
			mergeMissingConfigNodes(existing, value)
		}
	}
}

func removeLegacyNode(root *yaml.Node, path string) bool {
	parts := strings.Split(path, ".")
	parent := root
	for _, part := range parts[:len(parts)-1] {
		parent = findConfigNode(parent, part)
		if parent == nil {
			return false
		}
	}
	if parent.Kind != yaml.MappingNode {
		return false
	}
	key := parts[len(parts)-1]
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			parent.Content = append(parent.Content[:i], parent.Content[i+2:]...)
			return true
		}
	}
	return false
}

func backupAndWriteConfig(path string, content []byte) error {
	original, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := atomicConfigWrite(path+".bak", original); err != nil {
		return fmt.Errorf("backup original configuration: %w", err)
	}
	if err := atomicConfigWrite(path, content); err != nil {
		return fmt.Errorf("write migrated configuration: %w", err)
	}
	return nil
}

func atomicConfigWrite(path string, content []byte) error {
	dir := filepath.Dir(path)
	if err := ensureConfigFileDirectory(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".config-migrate-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func legacyFooterHTML(value *yaml.Node, escape bool) *yaml.Node {
	body := value.Value
	if escape {
		body = "<p>" + html.EscapeString(body) + "</p>"
	}
	return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: "format"}, {Kind: yaml.ScalarNode, Tag: "!!str", Value: "html"},
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: "body"}, {Kind: yaml.ScalarNode, Tag: "!!str", Value: body},
	}}
}
