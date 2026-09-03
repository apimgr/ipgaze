package path

import (
	"errors"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// validPathSegment matches lowercase alphanumeric, hyphens, underscores
var validPathSegment = regexp.MustCompile(`^[a-z0-9_-]+$`)

var (
	// ErrPathTraversal indicates an attempted path traversal attack
	ErrPathTraversal = errors.New("path traversal detected")
	// ErrInvalidPath indicates an invalid or malformed path
	ErrInvalidPath = errors.New("invalid path")
	// ErrPathTooLong indicates the path exceeds maximum allowed length
	ErrPathTooLong = errors.New("path exceeds maximum length")
	// ErrPathOutsideBase indicates path escapes the allowed base directory
	ErrPathOutsideBase = errors.New("path outside allowed directory")
)

// SafePath validates and normalizes a path, preventing traversal attacks.
// It returns the cleaned path relative to the base directory.
// Returns an error if the path attempts to escape the base directory.
func SafePath(base, requestPath string) (string, error) {
	if base == "" {
		return "", ErrInvalidPath
	}
	if requestPath == "" {
		return base, nil
	}

	// Clean the base path first
	cleanBase := filepath.Clean(base)

	// Reject paths containing null bytes (common attack vector)
	if strings.ContainsRune(requestPath, 0) {
		return "", ErrPathTraversal
	}

	// Clean the requested path
	cleanPath := filepath.Clean(requestPath)

	// Reject explicit traversal patterns before joining
	if containsTraversal(requestPath) || containsTraversal(cleanPath) {
		return "", ErrPathTraversal
	}

	// Join and clean the full path
	fullPath := filepath.Join(cleanBase, cleanPath)
	fullPath = filepath.Clean(fullPath)

	// Verify the resulting path is within the base directory
	// Use filepath.Rel to check if path escapes base
	rel, err := filepath.Rel(cleanBase, fullPath)
	if err != nil {
		return "", ErrPathOutsideBase
	}

	// Check if relative path escapes (starts with ..)
	if strings.HasPrefix(rel, "..") || rel == ".." {
		return "", ErrPathOutsideBase
	}

	return fullPath, nil
}

// containsTraversal checks for path traversal patterns
func containsTraversal(path string) bool {
	// Normalize separators for consistent checking
	normalized := filepath.ToSlash(path)

	// Check for obvious traversal patterns
	patterns := []string{
		"..",
		"./.",
		"..\\",
		"\\..\\",
	}

	for _, pattern := range patterns {
		if strings.Contains(normalized, pattern) {
			return true
		}
	}

	// Check for encoded traversal attempts
	// Patterns: "..", "../", "..\", and overlong encodings
	encodedPatterns := []string{
		"%2e%2e",
		"%2e%2e/",
		"..%2f",
		"%2e%2e%2f",
		"..%5c",
		"%2e%2e%5c",
		"..%c0%af",
		"..%c1%9c",
	}

	lowerPath := strings.ToLower(normalized)
	for _, pattern := range encodedPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}

	return false
}

// NormalizeURLPath normalizes a URL path for consistent routing.
// Removes double slashes, normalizes case, and removes trailing slashes (except root).
func NormalizeURLPath(path string) string {
	if path == "" || path == "/" {
		return "/"
	}

	// Replace backslashes with forward slashes
	path = strings.ReplaceAll(path, "\\", "/")

	// Remove consecutive slashes
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}

	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// Remove trailing slash (except for root)
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}

	// Clean the path (handles . and .. within URL)
	path = filepath.ToSlash(filepath.Clean(path))

	return path
}

// IsPathSafe checks if a path is safe without transforming it.
// Returns true if the path does not contain traversal patterns.
func IsPathSafe(path string) bool {
	return !containsTraversal(path)
}

// ValidateFilename validates a filename (not a path) for safety.
// Rejects names with path separators or traversal patterns.
func ValidateFilename(name string) error {
	if name == "" {
		return ErrInvalidPath
	}

	// Check for null bytes
	if strings.ContainsRune(name, 0) {
		return ErrPathTraversal
	}

	// Reject path separators in filename
	if strings.ContainsAny(name, "/\\") {
		return ErrInvalidPath
	}

	// Reject traversal patterns
	if name == "." || name == ".." {
		return ErrPathTraversal
	}

	// Reject names starting with . followed by another .
	if strings.HasPrefix(name, "..") {
		return ErrPathTraversal
	}

	return nil
}

// normalizePath cleans a path for safe use
// Strips leading/trailing slashes, collapses multiple slashes, removes traversal
func normalizePath(input string) string {
	if input == "" {
		return ""
	}

	// Use path.Clean to handle .., ., and //
	cleaned := path.Clean(input)

	// Strip leading/trailing slashes
	cleaned = strings.Trim(cleaned, "/")

	// Reject if still contains .. after cleaning
	if strings.Contains(cleaned, "..") {
		return ""
	}

	return cleaned
}

// validatePathSegment checks a single path segment
func validatePathSegment(segment string) error {
	if segment == "" {
		return ErrInvalidPath
	}
	if len(segment) > 64 {
		return ErrPathTooLong
	}
	if !validPathSegment.MatchString(segment) {
		return ErrInvalidPath
	}
	if segment == "." || segment == ".." {
		return ErrPathTraversal
	}
	return nil
}

// validatePath checks an entire path
func validatePath(p string) error {
	if len(p) > 2048 {
		return ErrPathTooLong
	}

	// Check for traversal attempts before normalization
	if strings.Contains(p, "..") {
		return ErrPathTraversal
	}

	// Check each segment
	segments := strings.Split(strings.Trim(p, "/"), "/")
	for _, seg := range segments {
		if seg == "" {
			continue
		}
		if err := validatePathSegment(seg); err != nil {
			return err
		}
	}

	return nil
}

// SafePathSimple normalizes and validates a single path input
// Returns error if invalid (per PART 5 spec)
func SafePathSimple(input string) (string, error) {
	if err := validatePath(input); err != nil {
		return "", err
	}
	return normalizePath(input), nil
}

// SafeFilePath ensures path stays within base directory
func SafeFilePath(baseDir, userPath string) (string, error) {
	// Normalize user input
	safe, err := SafePathSimple(userPath)
	if err != nil {
		return "", err
	}

	// Construct full path
	fullPath := filepath.Join(baseDir, safe)

	// Resolve to absolute
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return "", err
	}

	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", err
	}

	// Verify path is still within base
	if !strings.HasPrefix(absPath, absBase+string(filepath.Separator)) && absPath != absBase {
		return "", ErrPathTraversal
	}

	return absPath, nil
}
