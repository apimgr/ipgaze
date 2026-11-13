package email

import "embed"

// FS embeds the default email templates required by AI.md PART 17.
//
//go:embed *.txt
var FS embed.FS
