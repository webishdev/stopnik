package handler

import (
	"mime"
	"net/http"
	"path"
	"stopnik/internal/template/assets"
	"stopnik/log"
	"strings"
)

type AssetHandler struct {
}

func (handler *AssetHandler) Matches(r *http.Request) bool {
	currentPath, _ := path.Split(r.URL.Path)
	currentPath = strings.TrimSuffix(currentPath, "/")
	return strings.HasSuffix(currentPath, "/assets")
}

func (handler *AssetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodGet {

		assetsFS := assets.GetAssets()

		assetFSPath := assetFSPath(r.URL.Path)

		data, assetsFSError := assetsFS.ReadFile(assetFSPath)
		if assetsFSError != nil {
			NotFoundHandler(w, r)
			return
		}

		contentType := mime.TypeByExtension(path.Ext(assetFSPath))

		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		_, writeError := w.Write(data)
		if writeError != nil {
			log.Error("Could not send data: %v", writeError)
		}
	} else {
		MethodNotAllowedHandler(w, r)
		return
	}
}

func assetFSPath(value string) string {
	currentPath, currentFile := path.Split(value)
	currentPath = strings.TrimPrefix(currentPath, "/")
	currentPath = strings.TrimSuffix(currentPath, "/")
	parts := strings.Split(currentPath, "/")

	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if part == "assets" {
			parts[i] = "resources"
			break
		}
	}

	adjustedParts := append(parts, currentFile)

	return strings.Join(adjustedParts, "/")
}
