package assets

import (
	"embed"
)

//go:embed all:resources
var staticAssets embed.FS

func GetAssets() (embed.FS, error) {
	return staticAssets, nil
}
