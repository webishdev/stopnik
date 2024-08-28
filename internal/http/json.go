package http

import (
	"encoding/json"
	"net/http"
)

func SendJson(value any, w http.ResponseWriter) error {
	return SendJsonWithStatus(value, w, http.StatusOK)
}

func SendJsonWithStatus(value any, w http.ResponseWriter, statusCode int) error {
	bytes, tokenMarshalError := json.Marshal(value)
	if tokenMarshalError != nil {
		return tokenMarshalError
	}

	w.Header().Set(ContentType, ContentTypeJSON)
	w.Header().Set(AccessControlAllowOrigin, "*")
	w.WriteHeader(statusCode)
	_, writeError := w.Write(bytes)
	if writeError != nil {
		return writeError
	}

	return nil
}
