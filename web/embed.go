package webassets

import "embed"

// Assets holds all embedded static CSS, icons, and HTML templates.
//
//go:embed static/* templates/*.html
var Assets embed.FS
