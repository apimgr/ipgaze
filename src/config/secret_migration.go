package config

import (
	"log"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func migrateConfiguredSecrets(path string, primary []byte) []byte {
	var primaryDoc yaml.Node
	if err := yaml.Unmarshal(primary, &primaryDoc); err != nil || len(primaryDoc.Content) == 0 || primaryDoc.Content[0].Kind != yaml.MappingNode {
		return primary
	}
	dropins, err := configDropInPaths(filepath.Join(filepath.Dir(path), "yaml.d"))
	if err != nil {
		log.Printf("config: secret migration skipped: %v", err)
		return primary
	}
	type sourceFile struct {
		path      string
		root      *yaml.Node
		isPrimary bool
	}
	sources := []sourceFile{{path: path, root: primaryDoc.Content[0], isPrimary: true}}
	merged := cloneYAMLNode(primaryDoc.Content[0])
	for _, dropin := range dropins {
		data, readErr := os.ReadFile(dropin)
		if readErr != nil {
			log.Printf("config: secret migration skipped for %s: %v", dropin, readErr)
			return primary
		}
		var document yaml.Node
		if parseErr := yaml.Unmarshal(data, &document); parseErr != nil || len(document.Content) == 0 || document.Content[0].Kind != yaml.MappingNode {
			log.Printf("config: secret migration skipped for %s: invalid YAML", dropin)
			return primary
		}
		sources = append(sources, sourceFile{path: dropin, root: document.Content[0]})
		mergeConfigNodes(merged, document.Content[0], "", dropin, map[string]string{}, &[]configOverride{})
	}
	secretPath := filepath.Join(filepath.Dir(path), "secrets.yml")
	var secretDoc yaml.Node
	if data, readErr := os.ReadFile(secretPath); readErr == nil {
		if err := yaml.Unmarshal(data, &secretDoc); err != nil || len(secretDoc.Content) == 0 || secretDoc.Content[0].Kind != yaml.MappingNode {
			log.Printf("config: secret migration skipped: existing secrets.yml is invalid")
			return primary
		}
	} else if !os.IsNotExist(readErr) {
		log.Printf("config: secret migration skipped: %v", readErr)
		return primary
	} else {
		secretDoc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	secretRoot := secretDoc.Content[0]
	newSecrets := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	if !extractConfigSecrets(merged, newSecrets, "") {
		return primary
	}
	if err := validateSecretKeys(newSecrets, "", secretPath); err != nil {
		log.Printf("config: secret migration skipped: %v", err)
		return primary
	}
	mergeMissingConfigNodes(secretRoot, newSecrets)
	if findConfigNode(secretRoot, "server.ssl.letsencrypt.dns_credentials") != nil {
		combined := cloneYAMLNode(merged)
		mergeConfigNodes(combined, secretRoot, "", secretPath, map[string]string{}, &[]configOverride{})
		combinedBytes, marshalErr := yaml.Marshal(&yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{combined}})
		if marshalErr != nil {
			log.Printf("config: secret migration skipped: encode merged DNS credentials: %v", marshalErr)
			return primary
		}
		cfg := DefaultConfig()
		if unmarshalErr := yaml.Unmarshal(combinedBytes, cfg); unmarshalErr != nil {
			log.Printf("config: secret migration skipped: read merged DNS credentials: %v", unmarshalErr)
			return primary
		}
		if _, normalizeErr := normalizeDNSCredentials(cfg); normalizeErr != nil {
			log.Printf("config: secret migration skipped: encrypt DNS credentials: %v", normalizeErr)
			return primary
		}
		if cfg.Server.Security.EncryptionKey != "" {
			setConfigNode(secretRoot, "server.security.encryption_key", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: cfg.Server.Security.EncryptionKey})
			if findConfigNode(secretRoot, "server.security.encryption_key_version") == nil {
				setConfigNode(secretRoot, "server.security.encryption_key_version", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "1"})
			}
		}
		dnsBytes, marshalErr := yaml.Marshal(cfg.Server.SSL.LetsEncrypt.DNSCredentials)
		if marshalErr != nil {
			log.Printf("config: secret migration skipped: encode encrypted DNS credentials: %v", marshalErr)
			return primary
		}
		var dnsDoc yaml.Node
		if unmarshalErr := yaml.Unmarshal(dnsBytes, &dnsDoc); unmarshalErr != nil || len(dnsDoc.Content) == 0 {
			log.Printf("config: secret migration skipped: decode encrypted DNS credentials")
			return primary
		}
		setConfigNode(secretRoot, "server.ssl.letsencrypt.dns_credentials", dnsDoc.Content[0])
	}
	encodedSecrets, err := yaml.Marshal(&secretDoc)
	if err != nil {
		log.Printf("config: secret migration skipped: encode secrets: %v", err)
		return primary
	}
	if err := atomicPrivateWrite(secretPath, encodedSecrets); err != nil {
		log.Printf("config: secret migration could not persist secrets.yml: %v", err)
		return primary
	}
	var newPrimary []byte
	for _, source := range sources {
		removed := removeConfigSecrets(source.root, "")
		if !removed {
			continue
		}
		pruneEmptyConfigMaps(source.root)
		document := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{source.root}}
		data, marshalErr := yaml.Marshal(document)
		if marshalErr != nil {
			log.Printf("config: could not rewrite secrets from %s: %v", source.path, marshalErr)
			continue
		}
		writePath := source.path
		if !source.isPrimary {
			if info, statErr := os.Lstat(writePath); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
				resolved, resolveErr := filepath.EvalSymlinks(writePath)
				if resolveErr != nil {
					log.Printf("config: could not resolve secret-bearing drop-in %s: %v", writePath, resolveErr)
					continue
				}
				writePath = resolved
			}
		}
		if source.isPrimary {
			newPrimary = data
			if err := backupAndWriteConfig(path, data); err != nil {
				log.Printf("config: could not remove migrated secrets from %s: %v", path, err)
				newPrimary = nil
			}
		} else if err := atomicConfigWrite(writePath, data); err != nil {
			log.Printf("config: could not remove migrated secrets from %s: %v", writePath, err)
		}
	}
	if newPrimary != nil {
		return newPrimary
	}
	return primary
}

func extractConfigSecrets(source, destination *yaml.Node, prefix string) bool {
	selected, found := secretConfigSubset(source, prefix)
	if !found {
		return false
	}
	mergeMissingConfigNodes(destination, selected)
	return true
}

func secretConfigSubset(source *yaml.Node, prefix string) (*yaml.Node, bool) {
	if source == nil {
		return nil, false
	}
	if isSecretConfigValue(prefix, source) {
		return cloneYAMLNode(source), true
	}
	selected := cloneYAMLNode(source)
	found := false
	switch source.Kind {
	case yaml.MappingNode:
		selected.Content = nil
		for index := 0; index+1 < len(source.Content); index += 2 {
			key, value := source.Content[index], source.Content[index+1]
			path := key.Value
			if prefix != "" {
				path = prefix + "." + path
			}
			if subset, ok := secretConfigSubset(value, path); ok {
				selected.Content = append(selected.Content, cloneYAMLNode(key), subset)
				found = true
			}
		}
	case yaml.SequenceNode:
		selected.Content = make([]*yaml.Node, 0, len(source.Content))
		for _, child := range source.Content {
			subset, ok := secretConfigSubset(child, prefix+"[]")
			if !ok {
				subset = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			}
			selected.Content = append(selected.Content, subset)
			found = found || ok
		}
	default:
		return nil, false
	}
	return selected, found
}

func removeConfigSecrets(source *yaml.Node, prefix string) bool {
	if source == nil || source.Kind != yaml.MappingNode {
		return false
	}
	changed := false
	for index := 0; index+1 < len(source.Content); {
		key := source.Content[index].Value
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		if isSecretConfigValue(path, source.Content[index+1]) {
			source.Content = append(source.Content[:index], source.Content[index+2:]...)
			changed = true
			continue
		}
		value := source.Content[index+1]
		if value.Kind == yaml.MappingNode && removeConfigSecrets(value, path) {
			changed = true
		}
		if value.Kind == yaml.SequenceNode {
			for _, child := range value.Content {
				if child.Kind == yaml.MappingNode && removeConfigSecrets(child, path+"[]") {
					changed = true
				}
			}
		}
		index += 2
	}
	return changed
}
