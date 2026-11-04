package assets

import (
	"crypto/sha1"
	"fmt"
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

func NewAssetHandler() *Handler {
	currentConfig := config.GetConfigInstance()
	return &Handler{
		config:       currentConfig,
		errorHandler: internalError.NewErrorHandler(),
	}
}

func (h *Handler) Matches(r *http.Request) bool {
	currentPath, _ := path.Split(r.URL.Path)
	currentPath = strings.TrimSuffix(currentPath, "/")
	return currentPath == h.config.GetBasePath()+"/assets"
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.AccessLogRequest(r)
	if r.Method == http.MethodGet {

		assetsFS := assets.GetAssets()

		assetFSPath := getAssetFSPath(r.URL.Path)

		var result []byte
		contentType := mime.TypeByExtension(path.Ext(assetFSPath))
		if assetFSPath == "resources/logo.png" && h.config.GetLogoImage() != nil {
			logoImage := h.config.GetLogoImage()
			result = *logoImage
			contentType = mime.TypeByExtension(path.Ext(h.config.UI.LogoImage))
		} else {
			data, assetsFSError := assetsFS.ReadFile(assetFSPath)
			if assetsFSError != nil {
				h.errorHandler.NotFoundHandler(w, r)
				return
			}
			result = data
		}

		// The system may not know all extensions, e.g. without MIME database in a container image,
		// as browsers do not sniff the content (X-Content-Type-Options: nosniff), a content type is required
		if contentType == "" {
			contentType = http.DetectContentType(result)
		}

		requestData := internalHttp.NewRequestData(r)
		responseWriter := internalHttp.NewResponseWriter(w, requestData)

		etagValue := fmt.Sprintf("%x", sha1.Sum(result))

		responseWriter.SetEncodingHeader()
		w.Header().Set(internalHttp.ContentType, contentType)
		w.Header().Set(internalHttp.CacheControl, "public, max-age=14400") // 4 hours = 14400 = 3600 * 4
		w.Header().Set(internalHttp.ETag, etagValue)
		w.WriteHeader(http.StatusOK)

		_, writeError := responseWriter.Write(result)
		if writeError != nil {
			log.Error("Could not send compressed data: %v", writeError)
		}
	} else {
		h.errorHandler.MethodNotAllowedHandler(w, r)
		return
	}
}

// getAssetFSPath maps a requested asset to the embedded resources, e.g. /auth/assets/styles.css to resources/styles.css.
func getAssetFSPath(value string) string {
	_, currentFile := path.Split(value)
	return path.Join("resources", currentFile)
}
