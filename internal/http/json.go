package http

import (
	"encoding/json"
	"net/http"
)

func SendJson(value any, w http.ResponseWriter) error {
	bytes, tokenMarshalError := json.Marshal(value)
	if tokenMarshalError != nil {
		return tokenMarshalError
	}

	w.Header().Set(ContentType, ContentTypeJSON)
	_, writeError := w.Write(bytes)
	if writeError != nil {
		return writeError
	}

	return nil
}
