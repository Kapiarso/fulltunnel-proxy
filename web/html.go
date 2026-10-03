package web

import (
	"embed"
	_ "embed"
)

//go:embed templates/index.html
var IndexHTML string

//go:embed static/*
var StaticFS embed.FS
