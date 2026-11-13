//go:build windows

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/apimgr/ipgaze/src/paths"
	"golang.org/x/sys/windows/svc"
)

// IsRunningAsService reports whether the current process is running under the
// Windows Service Control Manager.
func IsRunningAsService() bool {
	isService, err := svc.IsWindowsService()
	return err == nil && isService
}

func prepareServiceDirectories(dirs paths.Directories, binDir string) error {
	serviceAccount := fmt.Sprintf(`NT SERVICE\%s`, appName)
	directories := []string{
		dirs.Config, dirs.Data, dirs.Logs, dirs.Cache, dirs.SSL,
		dirs.Security, dirs.DB, dirs.Backup, filepath.Dir(dirs.PID),
	}
	seen := make(map[string]struct{}, len(directories))
	for _, directory := range directories {
		if directory == "" {
			continue
		}
		clean := filepath.Clean(directory)
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		if err := os.MkdirAll(clean, 0o750); err != nil {
			return fmt.Errorf("create service directory %q: %w", clean, err)
		}
		grant := serviceAccount + `:(OI)(CI)F`
		if output, err := exec.Command("icacls.exe", clean, "/grant", grant, "/T", "/C").CombinedOutput(); err != nil {
			return fmt.Errorf("grant service account access to %q: %w: %s", clean, err, output)
		}
	}
	if output, err := exec.Command("icacls.exe", binDir, "/grant", serviceAccount+`:(OI)(CI)RX`, "/T", "/C").CombinedOutput(); err != nil {
		return fmt.Errorf("grant service account read access to %q: %w: %s", binDir, err, output)
	}
	return nil
}
