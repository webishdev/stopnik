package assets

import (
	"github.com/webishdev/stopnik/internal/config"
	internalHttp "github.com/webishdev/stopnik/internal/http"
	internalError "github.com/webishdev/stopnik/internal/server/handler/error"
	"github.com/webishdev/stopnik/internal/template/assets"
	"github.com/webishdev/stopnik/log"
	"mime"
	"net/http"
	"path"
	"strings"
)

type Handler struct {
	config       *config.Config
	errorHandler *internalError.Handler
}

func NewAssetHandler(config *config.Config) *Handler {
	return &Handler{
		config:       config,
		errorHandler: internalError.NewErrorHandler(),
	}
}

func (h *Handler) Matches(r *http.Request) bool {
	currentPath, _ := path.Split(r.URL.Path)
	currentPath = strings.TrimSuffix(currentPath, "/")
	return strings.HasSuffix(currentPath, "/assets")
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodGet {

		assetsFS := assets.GetAssets()

		assetFSPath := getAssetFSPath(r.URL.Path)

		var result []byte
		contentType := mime.TypeByExtension(path.Ext(assetFSPath))
		if assetFSPath == "resources/stopnik_250.png" && h.config.GetLogoImage() != nil {
			logoImage := h.config.GetLogoImage()
			result = *logoImage
			if h.config.UI.LogoContentType != "" {
				contentType = h.config.UI.LogoContentType
			}
		} else {
			data, assetsFSError := assetsFS.ReadFile(assetFSPath)
			if assetsFSError != nil {
				h.errorHandler.NotFoundHandler(w, r)
				return
			}
			result = data
		}

		w.Header().Set(internalHttp.ContentType, contentType)
		w.WriteHeader(http.StatusOK)
		_, writeError := w.Write(result)
		if writeError != nil {
			log.Error("Could not send data: %v", writeError)
		}
	} else {
		h.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}

func getAssetFSPath(value string) string {
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
