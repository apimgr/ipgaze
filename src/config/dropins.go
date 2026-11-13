package config

import (
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type configSource struct {
	path string
	node *yaml.Node
}

type configOverride struct {
	key    string
	oldSrc string
	newSrc string
}

func readConfigSource(path string) (configSource, error) {
	info, err := os.Stat(path)
	if err != nil {
		return configSource{}, fmt.Errorf("%s: stat configuration: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return configSource{}, fmt.Errorf("%s: configuration file is not regular", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return configSource{}, fmt.Errorf("%s: drop-in is group or world writable", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return configSource{}, fmt.Errorf("%s: read configuration: %w", path, err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return configSource{}, fmt.Errorf("%s: parse configuration: %w", path, err)
	}
	if len(doc.Content) == 0 {
		return configSource{path: path, node: &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}}, nil
	}
	if err := validateConfigYAMLNode(doc.Content[0], "", path); err != nil {
		return configSource{}, err
	}
	if doc.Content[0].Kind != yaml.MappingNode {
		return configSource{}, fmt.Errorf("%s:%d: configuration root must be a mapping", path, doc.Content[0].Line)
	}
	return configSource{path: path, node: &doc}, nil
}

func validateConfigYAMLNode(node *yaml.Node, keyPath, path string) error {
	if node.Tag == "!!null" {
		return fmt.Errorf("%s:%d: explicit null is not allowed for key %s", path, node.Line, configKeyName(keyPath))
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]struct{}, len(node.Content)/2)
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return fmt.Errorf("%s:%d: key %s must be a string", path, key.Line, configKeyName(keyPath))
			}
			if _, exists := seen[key.Value]; exists {
				fullKey := key.Value
				if keyPath != "" {
					fullKey = keyPath + "." + key.Value
				}
				return fmt.Errorf("%s:%d: duplicate configuration key %s", path, key.Line, fullKey)
			}
			seen[key.Value] = struct{}{}
			fullKey := key.Value
			if keyPath != "" {
				fullKey = keyPath + "." + key.Value
			}
			if err := validateConfigYAMLNode(value, fullKey, path); err != nil {
				return err
			}
		}
		return nil
	}
	for _, child := range node.Content {
		if err := validateConfigYAMLNode(child, keyPath, path); err != nil {
			return err
		}
	}
	return nil
}

func configKeyName(key string) string {
	if key == "" {
		return "<root>"
	}
	return key
}

func configDropInPaths(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: read drop-in directory: %w", dir, err)
	}
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, fmt.Errorf("%s: resolve drop-in directory: %w", dir, err)
	}
	resolvedDir, err = filepath.Abs(resolvedDir)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".bak") || strings.HasSuffix(name, "~") || strings.HasSuffix(name, ".orig") {
			continue
		}
		ext := filepath.Ext(name)
		if ext != ".yml" && ext != ".yaml" {
			continue
		}
		path := filepath.Join(dir, name)
		info, infoErr := entry.Info()
		if infoErr != nil {
			return nil, fmt.Errorf("%s: inspect drop-in: %w", path, infoErr)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			if info.Mode().IsRegular() {
				paths = append(paths, path)
			}
			continue
		}
		target, evalErr := filepath.EvalSymlinks(path)
		if evalErr != nil {
			return nil, fmt.Errorf("%s: resolve drop-in symlink: %w", path, evalErr)
		}
		targetAbs, absErr := filepath.Abs(target)
		if absErr != nil {
			return nil, absErr
		}
		if targetAbs != resolvedDir && !strings.HasPrefix(targetAbs, resolvedDir+string(filepath.Separator)) {
			continue
		}
		targetInfo, statErr := os.Stat(targetAbs)
		if statErr != nil {
			return nil, fmt.Errorf("%s: stat drop-in target: %w", path, statErr)
		}
		if targetInfo.Mode().IsRegular() {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	return paths, nil
}

func cloneYAMLNode(node *yaml.Node) *yaml.Node {
	clone := *node
	clone.Content = make([]*yaml.Node, len(node.Content))
	for i, child := range node.Content {
		clone.Content[i] = cloneYAMLNode(child)
	}
	return &clone
}

func collectConfigWinners(node *yaml.Node, prefix, source string, winners map[string]string) {
	if node.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		winners[path] = source
		collectConfigWinners(node.Content[i+1], path, source, winners)
	}
}

func mergeConfigNodes(dst, src *yaml.Node, prefix, source string, winners map[string]string, overrides *[]configOverride) {
	dstMap := yamlMapIndex(dst)
	for i := 0; i+1 < len(src.Content); i += 2 {
		keyNode, valueNode := src.Content[i], src.Content[i+1]
		key := keyNode.Value
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		if index, exists := dstMap[key]; exists {
			dstValue := dst.Content[index+1]
			if dstValue.Kind == yaml.MappingNode && valueNode.Kind == yaml.MappingNode {
				mergeConfigNodes(dstValue, valueNode, path, source, winners, overrides)
				continue
			}
			*overrides = append(*overrides, configOverride{key: path, oldSrc: winners[path], newSrc: source})
			dst.Content[index+1] = cloneYAMLNode(valueNode)
		} else {
			dst.Content = append(dst.Content, cloneYAMLNode(keyNode), cloneYAMLNode(valueNode))
		}
		markConfigWinners(valueNode, path, source, winners)
	}
}

func yamlMapIndex(node *yaml.Node) map[string]int {
	index := make(map[string]int, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		index[node.Content[i].Value] = i
	}
	return index
}

func markConfigWinners(node *yaml.Node, prefix, source string, winners map[string]string) {
	winners[prefix] = source
	collectConfigWinners(node, prefix, source, winners)
}

func mergedConfigFingerprint(path string) string {
	var value strings.Builder
	appendFingerprint(&value, path)
	dir := filepath.Join(filepath.Dir(path), "yaml.d")
	info, err := os.Stat(path)
	if err == nil {
		fmt.Fprintf(&value, "%d:%d:%d;", info.ModTime().UnixNano(), info.Size(), info.Mode())
	}
	if dirInfo, statErr := os.Stat(dir); statErr == nil {
		fmt.Fprintf(&value, "dir:%d;", dirInfo.ModTime().UnixNano())
	}
	paths, pathErr := configDropInPaths(dir)
	if pathErr != nil {
		appendFingerprint(&value, pathErr.Error())
	}
	for _, dropin := range paths {
		appendFingerprint(&value, dropin)
		if fileInfo, fileErr := os.Stat(dropin); fileErr == nil {
			fmt.Fprintf(&value, "%d:%d:%d;", fileInfo.ModTime().UnixNano(), fileInfo.Size(), fileInfo.Mode())
		}
	}
	return value.String()
}

func appendFingerprint(value *strings.Builder, part string) {
	value.WriteString(part)
	value.WriteByte(0)
}

func mergeYAMLForConfigFile(path string, data []byte) ([]byte, map[string]string, map[int]string, error) {
	var primaryDoc yaml.Node
	if err := yaml.Unmarshal(data, &primaryDoc); err != nil {
		return nil, nil, nil, fmt.Errorf("%s: parse configuration: %w", path, err)
	}
	if len(primaryDoc.Content) == 0 {
		primaryDoc.Content = []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}
	}
	if err := validateConfigYAMLNode(primaryDoc.Content[0], "", path); err != nil {
		return nil, nil, nil, err
	}
	if primaryDoc.Content[0].Kind != yaml.MappingNode {
		return nil, nil, nil, fmt.Errorf("%s:%d: configuration root must be a mapping", path, primaryDoc.Content[0].Line)
	}
	sources := []configSource{{path: path, node: &primaryDoc}}
	dropins, err := configDropInPaths(filepath.Join(filepath.Dir(path), "yaml.d"))
	if err != nil {
		return nil, nil, nil, err
	}
	winners := map[string]string{}
	collectConfigWinners(primaryDoc.Content[0], "", path, winners)
	var overrides []configOverride
	for _, dropin := range dropins {
		source, readErr := readConfigSource(dropin)
		if readErr != nil {
			return nil, nil, nil, readErr
		}
		mergeConfigNodes(primaryDoc.Content[0], source.node.Content[0], "", source.path, winners, &overrides)
		sources = append(sources, source)
	}
	for _, source := range sources[1:] {
		log.Printf("config: loaded drop-in %s", source.path)
	}
	for _, override := range overrides {
		slog.Debug("configuration drop-in overrides key", "key", override.key, "file", override.newSrc, "previous_file", override.oldSrc)
	}
	data, err = yaml.Marshal(&primaryDoc)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%s: marshal merged configuration: %w", path, err)
	}
	var mergedDoc yaml.Node
	if err := yaml.Unmarshal(data, &mergedDoc); err != nil {
		return nil, nil, nil, fmt.Errorf("%s: inspect merged configuration: %w", path, err)
	}
	lineKeys := make(map[int]string)
	if len(mergedDoc.Content) > 0 {
		collectConfigLineKeys(mergedDoc.Content[0], "", lineKeys)
	}
	return data, winners, lineKeys, nil
}

func parseMergedConfig(path string, data []byte) (*AppConfig, error) {
	merged, winners, lineKeys, err := mergeYAMLForConfigFile(path, data)
	if err != nil {
		return nil, err
	}
	cfg := DefaultConfig()
	if err := yaml.Unmarshal(merged, cfg); err != nil {
		var typeErr *yaml.TypeError
		if errors.As(err, &typeErr) {
			var problems []string
			for _, detail := range typeErr.Errors {
				var line int
				_, _ = fmt.Sscanf(detail, "line %d:", &line)
				key := lineKeys[line]
				if key == "" {
					key = "<unknown>"
				}
				source := winners[key]
				if source == "" {
					source = path
				}
				problems = append(problems, fmt.Sprintf("%s:%d: key %s: %s", source, line, key, detail))
			}
			return nil, errors.New(strings.Join(problems, "; "))
		}
		return nil, fmt.Errorf("%s: parse merged configuration: %w", path, err)
	}
	return cfg, nil
}

func configValidationError(path string, validationErr error) error {
	if validationErr == nil {
		return nil
	}
	key := strings.Fields(validationErr.Error())
	if len(key) == 0 {
		return validationErr
	}
	wanted := strings.TrimRight(key[0], ":")
	paths, err := configDropInPaths(filepath.Join(filepath.Dir(path), "yaml.d"))
	if err != nil {
		return validationErr
	}
	paths = append([]string{path}, paths...)
	source, line, matchedKey := path, 1, "<root>"
	for _, file := range paths {
		data, readErr := os.ReadFile(file)
		if readErr != nil {
			continue
		}
		var doc yaml.Node
		if yaml.Unmarshal(data, &doc) != nil || len(doc.Content) == 0 {
			continue
		}
		if foundLine, _, foundKey := findConfigKey(doc.Content[0], "", wanted); foundKey != "" {
			source, line, matchedKey = file, foundLine, wanted
		}
	}
	return fmt.Errorf("%s:%d: key %s: %w", source, line, matchedKey, validationErr)
}

func findConfigKey(node *yaml.Node, prefix, wanted string) (int, int, string) {
	bestLine, bestLength, bestKey := 0, 0, ""
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			keyNode, valueNode := node.Content[i], node.Content[i+1]
			key := keyNode.Value
			if prefix != "" {
				key = prefix + "." + key
			}
			if wanted == key || strings.HasPrefix(wanted, key+".") || strings.HasPrefix(wanted, key+"[") {
				if len(key) > bestLength {
					bestLine, bestLength, bestKey = keyNode.Line, len(key), key
				}
				if line, length, fullKey := findConfigKey(valueNode, key, wanted); length > bestLength {
					bestLine, bestLength, bestKey = line, length, fullKey
				}
			}
		}
		return bestLine, bestLength, bestKey
	}
	if node.Kind == yaml.SequenceNode {
		for index, child := range node.Content {
			key := fmt.Sprintf("%s[%d]", prefix, index)
			if wanted == key || strings.HasPrefix(wanted, key+".") {
				if len(key) > bestLength {
					bestLine, bestLength, bestKey = child.Line, len(key), key
				}
				if line, length, fullKey := findConfigKey(child, key, wanted); length > bestLength {
					bestLine, bestLength, bestKey = line, length, fullKey
				}
			}
		}
		return bestLine, bestLength, bestKey
	}
	if wanted == prefix {
		return node.Line, len(prefix), prefix
	}
	return 0, 0, ""
}

func collectConfigLineKeys(node *yaml.Node, prefix string, lines map[int]string) {
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i].Value
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			lines[node.Content[i].Line] = path
			lines[node.Content[i+1].Line] = path
			collectConfigLineKeys(node.Content[i+1], path, lines)
		}
		return
	}
	for _, child := range node.Content {
		lines[child.Line] = prefix
		collectConfigLineKeys(child, prefix, lines)
	}
}
