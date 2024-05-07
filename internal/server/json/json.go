package json

import (
	"encoding/json"
	"net/http"
	internalHttp "stopnik/internal/http"
)

func SendJson(value any, w http.ResponseWriter) error {
	bytes, tokenMarshalError := json.Marshal(value)
	if tokenMarshalError != nil {
		return tokenMarshalError
	}

	w.Header().Set(internalHttp.ContentType, internalHttp.ContentTypeJSON)
	_, writeError := w.Write(bytes)
	if writeError != nil {
		return writeError
	}

	return nil
}
