package config

import (
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const areaConfigHeader = "# Settings of this node only (listen, identity, database, cache, ssl). Everything else lives in yaml.d/: branding.yml, web.yml, pages.yml, contact.yml, privacy.yml, security.yml, logs.yml, metrics.yml, notifications.yml, tor.yml, i2p.yml, maintenance.yml, app.yml. Credentials live in secrets.yml.\n"

type configArea struct {
	file  string
	paths []string
}

var configAreas = []configArea{
	{file: "branding.yml", paths: []string{"server.branding", "server.seo", "web.ui"}},
	{file: "web.yml", paths: []string{
		"server.cors", "server.csrf", "server.url_detection", "server.compression", "server.healthz", "server.i18n",
	}},
	{file: "pages.yml", paths: []string{"server.pages"}},
	{file: "contact.yml", paths: []string{"server.contact"}},
	{file: "privacy.yml", paths: []string{"server.privacy", "server.compliance", "server.tracking"}},
	{file: "security.yml", paths: []string{
		"server.security", "server.rate_limit", "server.geoip", "server.limits", "server.tokens", "data",
	}},
	{file: "logs.yml", paths: []string{"server.logs"}},
	{file: "metrics.yml", paths: []string{"server.metrics"}},
	{file: "notifications.yml", paths: []string{"server.notifications"}},
	{file: "tor.yml", paths: []string{"server.tor", "tor"}},
	{file: "i2p.yml", paths: []string{"server.i2p"}},
	{file: "maintenance.yml", paths: []string{
		"server.maintenance", "server.scheduler", "server.update", "server.auto_update", "server.backup", "server.restore", "server.cli",
	}},
}

var serverLocalKeys = map[string]bool{
	"token": true, "port": true, "address": true, "fqdn": true, "mode": true, "api_version": true,
	"baseurl": true, "pidfile": true, "daemonize": true, "debug": true,
	"database": true, "cache": true, "ssl": true, "trusted_proxies": true, "cluster": true,
}

func serverConfigOnly(content []byte) []byte {
	var document yaml.Node
	if err := yaml.Unmarshal(content, &document); err != nil || len(document.Content) == 0 || document.Content[0].Kind != yaml.MappingNode {
		return content
	}
	root := document.Content[0]
	server := findConfigNode(root, "server")
	if server != nil && server.Kind == yaml.MappingNode {
		remaining := make([]*yaml.Node, 0, len(server.Content))
		for index := 0; index+1 < len(server.Content); index += 2 {
			if serverLocalKeys[server.Content[index].Value] {
				remaining = append(remaining, server.Content[index], server.Content[index+1])
			}
		}
		server.Content = remaining
	}
	for index := 0; index+1 < len(root.Content); {
		key := root.Content[index].Value
		if key == "server" || key == "database" {
			index += 2
			continue
		}
		root.Content = append(root.Content[:index], root.Content[index+2:]...)
	}
	document.Content[0].HeadComment = ""
	data, err := yaml.Marshal(&document)
	if err != nil {
		return content
	}
	return append([]byte(areaConfigHeader), data...)
}

func saveInitialBranding(path, title, tagline string) error {
	branding := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	if title != "" {
		setConfigNode(branding, "title", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: title})
	}
	if tagline != "" {
		setConfigNode(branding, "tagline", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: tagline})
	}
	if len(branding.Content) == 0 {
		return nil
	}
	areaRoot := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	setConfigNode(areaRoot, "server.branding", branding)
	document := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{areaRoot}}
	data, err := yaml.Marshal(document)
	if err != nil {
		return err
	}
	dir := filepath.Join(filepath.Dir(path), "yaml.d")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return atomicPrivateWrite(filepath.Join(dir, "branding.yml"), data)
}

func migrateConfigAreas(path string, content []byte) []byte {
	var sourceDoc yaml.Node
	if err := yaml.Unmarshal(content, &sourceDoc); err != nil || len(sourceDoc.Content) == 0 || sourceDoc.Content[0].Kind != yaml.MappingNode {
		return content
	}
	sourceRoot := sourceDoc.Content[0]
	areas := make(map[string]*yaml.Node)
	changed := false
	for _, area := range configAreas {
		for _, keyPath := range area.paths {
			if keyPath == "server.security" && containsDeferredDatabaseSecrets(findConfigNode(sourceRoot, keyPath)) {
				continue
			}
			node := takeConfigNode(sourceRoot, keyPath)
			if node == nil {
				continue
			}
			changed = true
			mergeAreaDropIns(path, keyPath, node)
			areaRoot := ensureAreaRoot(areas, area.file)
			setConfigNode(areaRoot, keyPath, node)
		}
	}
	if web := findConfigNode(sourceRoot, "web"); web != nil && web.Kind == yaml.MappingNode {
		webArea := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		remaining := make([]*yaml.Node, 0, len(web.Content))
		for index := 0; index+1 < len(web.Content); index += 2 {
			key, value := web.Content[index], web.Content[index+1]
			if key.Value == "ui" {
				remaining = append(remaining, key, value)
				continue
			}
			webArea.Content = append(webArea.Content, cloneYAMLNode(key), cloneYAMLNode(value))
		}
		if len(webArea.Content) > 0 {
			changed = true
			setConfigNode(ensureAreaRoot(areas, "web.yml"), "web", webArea)
		}
		web.Content = remaining
		if len(remaining) == 0 {
			removeAreaNode(sourceRoot, "web")
		}
	}
	if server := findConfigNode(sourceRoot, "server"); server != nil && server.Kind == yaml.MappingNode {
		appServer := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		remaining := make([]*yaml.Node, 0, len(server.Content))
		for index := 0; index+1 < len(server.Content); index += 2 {
			key, value := server.Content[index], server.Content[index+1]
			if serverLocalKeys[key.Value] || key.Value == "security" && containsDeferredDatabaseSecrets(value) {
				remaining = append(remaining, key, value)
				continue
			}
			appServer.Content = append(appServer.Content, cloneYAMLNode(key), cloneYAMLNode(value))
		}
		if len(appServer.Content) > 0 {
			changed = true
			setConfigNode(ensureAreaRoot(areas, "app.yml"), "server", appServer)
		}
		server.Content = remaining
		if len(remaining) == 0 {
			removeAreaNode(sourceRoot, "server")
		}
	}
	knownTopLevel := map[string]bool{"server": true, "web": true, "tor": true, "database": true}
	appRoot := ensureAreaRoot(areas, "app.yml")
	for index := 0; index+1 < len(sourceRoot.Content); {
		key, value := sourceRoot.Content[index], sourceRoot.Content[index+1]
		if knownTopLevel[key.Value] {
			index += 2
			continue
		}
		changed = true
		setConfigNode(appRoot, key.Value, cloneYAMLNode(value))
		sourceRoot.Content = append(sourceRoot.Content[:index], sourceRoot.Content[index+2:]...)
	}
	if !changed {
		return content
	}
	if len(appRoot.Content) == 0 {
		delete(areas, "app.yml")
	}
	return writeConfigAreas(path, content, sourceDoc, areas)
}

func mergeAreaDropIns(path, keyPath string, destination *yaml.Node) {
	dropins, err := configDropInPaths(filepath.Join(filepath.Dir(path), "yaml.d"))
	if err != nil {
		return
	}
	for _, dropin := range dropins {
		data, readErr := os.ReadFile(dropin)
		if readErr != nil {
			continue
		}
		var document yaml.Node
		if yaml.Unmarshal(data, &document) != nil || len(document.Content) == 0 || document.Content[0].Kind != yaml.MappingNode {
			continue
		}
		if source := findConfigNode(document.Content[0], keyPath); source != nil && source.Kind == yaml.MappingNode && destination.Kind == yaml.MappingNode {
			mergeConfigNodes(destination, source, keyPath, dropin, map[string]string{}, &[]configOverride{})
		}
	}
}

func containsDeferredDatabaseSecrets(node *yaml.Node) bool {
	for _, key := range []string{
		"installation_secret", "installation_secret_previous", "installation_secret_previous_expires",
		"encryption_key_previous", "encryption_key_previous_expires",
	} {
		if findConfigNode(node, key) != nil {
			return true
		}
	}
	return false
}

func ensureAreaRoot(areas map[string]*yaml.Node, filename string) *yaml.Node {
	if root := areas[filename]; root != nil {
		return root
	}
	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	areas[filename] = root
	return root
}

func takeConfigNode(root *yaml.Node, path string) *yaml.Node {
	node := findConfigNode(root, path)
	if node == nil {
		return nil
	}
	removeAreaNode(root, path)
	return cloneYAMLNode(node)
}

func removeAreaNode(root *yaml.Node, path string) {
	parts := splitConfigPath(path)
	parent := root
	for _, part := range parts[:len(parts)-1] {
		parent = findConfigNode(parent, part)
		if parent == nil || parent.Kind != yaml.MappingNode {
			return
		}
	}
	key := parts[len(parts)-1]
	for index := 0; index+1 < len(parent.Content); index += 2 {
		if parent.Content[index].Value == key {
			parent.Content = append(parent.Content[:index], parent.Content[index+2:]...)
			return
		}
	}
}

func splitConfigPath(path string) []string {
	return strings.Split(path, ".")
}

func writeConfigAreas(path string, original []byte, serverDoc yaml.Node, areas map[string]*yaml.Node) []byte {
	dir := filepath.Join(filepath.Dir(path), "yaml.d")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Printf("config: area migration for %s skipped: %v", path, err)
		return original
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		log.Printf("config: area migration for %s skipped: %v", path, err)
		return original
	}
	filenames := make([]string, 0, len(areas))
	for filename := range areas {
		filenames = append(filenames, filename)
	}
	sort.Strings(filenames)
	existingRoots := make(map[string]*yaml.Node)
	writePaths := make(map[string]string)
	for _, filename := range filenames {
		areaPath := filepath.Join(dir, filename)
		info, err := os.Lstat(areaPath)
		if err != nil && !os.IsNotExist(err) {
			log.Printf("config: area migration for %s skipped: inspect %s: %v", path, areaPath, err)
			return original
		}
		if err == nil {
			readPath := areaPath
			if info.Mode()&os.ModeSymlink != 0 {
				resolved, resolveErr := filepath.EvalSymlinks(areaPath)
				if resolveErr != nil {
					log.Printf("config: area migration for %s skipped: resolve %s: %v", path, areaPath, resolveErr)
					return original
				}
				base, baseErr := filepath.Abs(dir)
				resolved, resolveErr = filepath.Abs(resolved)
				if baseErr != nil || resolveErr != nil {
					log.Printf("config: area migration for %s skipped: resolve %s: %v", path, areaPath, firstError(baseErr, resolveErr))
					return original
				}
				relative, relErr := filepath.Rel(base, resolved)
				if relErr != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
					log.Printf("config: area migration for %s skipped: %s points outside yaml.d", path, areaPath)
					return original
				}
				readPath = resolved
				writePaths[filename] = resolved
				info, err = os.Stat(resolved)
				if err != nil {
					log.Printf("config: area migration for %s skipped: inspect %s: %v", path, resolved, err)
					return original
				}
			} else {
				writePaths[filename] = areaPath
			}
			if !info.Mode().IsRegular() {
				log.Printf("config: area migration for %s skipped: %s is not a regular file", path, areaPath)
				return original
			}
			data, readErr := os.ReadFile(readPath)
			if readErr != nil {
				log.Printf("config: area migration for %s skipped: read %s: %v", path, readPath, readErr)
				return original
			}
			var doc yaml.Node
			if parseErr := yaml.Unmarshal(data, &doc); parseErr != nil || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
				log.Printf("config: area migration for %s skipped: %s cannot be parsed as a mapping", path, areaPath)
				return original
			}
			existingRoots[filename] = doc.Content[0]
			mergeMissingConfigNodes(existingRoots[filename], areas[filename])
		} else {
			existingRoots[filename] = areas[filename]
			writePaths[filename] = areaPath
		}
	}
	if err := atomicConfigWrite(path+".bak", original); err != nil {
		log.Printf("config: area migration for %s skipped: backup failed: %v", path, err)
		return original
	}
	for _, filename := range filenames {
		doc := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{existingRoots[filename]}}
		data, err := yaml.Marshal(doc)
		if err != nil {
			log.Printf("config: area migration for %s skipped: encode %s: %v", path, filename, err)
			return original
		}
		if err := atomicConfigWrite(writePaths[filename], data); err != nil {
			log.Printf("config: area migration for %s incomplete at %s: %v", path, filename, err)
			return original
		}
	}
	serverDoc.Content[0].HeadComment = ""
	data, err := yaml.Marshal(&serverDoc)
	if err != nil {
		log.Printf("config: area migration for %s skipped: encode server file: %v", path, err)
		return original
	}
	data = append([]byte(areaConfigHeader), data...)
	if err := atomicConfigWrite(path, data); err != nil {
		log.Printf("config: area migration for %s incomplete while writing server file: %v", path, err)
		return original
	}
	return data
}

func firstError(first, second error) error {
	if first != nil {
		return first
	}
	return second
}
