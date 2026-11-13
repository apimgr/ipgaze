//go:build !gui || (!linux && !darwin && !windows)

package gui

import (
	"errors"

	"github.com/apimgr/ipgaze/src/client/api"
)

var errUnavailable = errors.New("GUI support is not built for this platform")

func IsGUIAvailable() bool { return false }

func LaunchGUI(_ *api.APIClient, _, _ string) error { return errUnavailable }

func LaunchSetupWizard(_, _, _ string) (string, string, bool, bool, error) {
	return "", "", false, false, errUnavailable
}
