package http

import (
	"encoding/json"
	"net/http"
)

func SendJson(value any, w http.ResponseWriter, r *http.Request) error {
	return SendJsonWithStatus(value, http.StatusOK, w, r)
}

func SendJsonWithStatus(value any, statusCode int, w http.ResponseWriter, r *http.Request) error {
	bytes, tokenMarshalError := json.Marshal(value)
	if tokenMarshalError != nil {
		return tokenMarshalError
	}

	requestData := NewRequestData(r)
	responseWriter := NewResponseWriter(w, requestData)

	responseWriter.SetEncodingHeader()

	w.Header().Set(ContentType, ContentTypeJSON)
	w.Header().Set(CacheControl, "private, no-store")
	w.Header().Set(AccessControlAllowOrigin, "*")
	w.WriteHeader(statusCode)

	_, writeError := responseWriter.Write(bytes)
	if writeError != nil {
		return writeError
	}

	return nil
}
