package config

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type legacySecretStore interface {
	Write(context.Context, func(*sql.Tx) error) error
}

func ImportLegacyDatabaseSecrets(db legacySecretStore, path string) error {
	if db == nil {
		return fmt.Errorf("database is unavailable")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil || len(document.Content) == 0 {
		return err
	}
	root := document.Content[0]
	keys := []string{
		"server.security.installation_secret",
		"server.security.installation_secret_previous",
		"server.security.installation_secret_previous_expires",
		"server.security.encryption_key_previous",
		"server.security.encryption_key_previous_expires",
	}
	values := make(map[string]string)
	for _, key := range keys {
		if node := findConfigNode(root, key); node != nil {
			values[key[strings.LastIndex(key, ".")+1:]] = node.Value
		}
	}
	if len(values) == 0 {
		return nil
	}
	if err := db.Write(context.Background(), func(tx *sql.Tx) error {
		for name, value := range values {
			if _, err := tx.Exec(`INSERT OR IGNORE INTO app_secrets (name, value, updated_at) VALUES (?, ?, ?)`, name, value, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
				return fmt.Errorf("import legacy secret %s: %w", name, err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("import legacy secrets: %w", err)
	}
	for _, key := range keys {
		removeLegacyNode(root, key)
	}
	migrated, err := yaml.Marshal(&document)
	if err != nil {
		return fmt.Errorf("encode config after legacy secret import: %w", err)
	}
	if err := backupAndWriteConfig(path, migrated); err != nil {
		return err
	}
	migrateConfigAreas(path, migrated)
	return nil
}
