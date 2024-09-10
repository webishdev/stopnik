package http

import (
	"compress/gzip"
	"github.com/webishdev/stopnik/internal/system"
	"net/http"
)

type ResponseWriter struct {
	requestData   *RequestData
	w             http.ResponseWriter
	headerWritten bool
}

func NewResponseWriter(w http.ResponseWriter, requestData *RequestData) *ResponseWriter {
	return &ResponseWriter{
		requestData:   requestData,
		w:             w,
		headerWritten: false,
	}
}

func (rw *ResponseWriter) SetEncodingHeader() {
	compressionMethod, acceptCompressed := rw.requestData.AcceptCompressed()
	if acceptCompressed {
		switch *compressionMethod {
		case CompressionMethodGZip:
			rw.w.Header().Set(ContentEncoding, string(CompressionMethodGZip))
			rw.headerWritten = true
			return
		}

	}
}

func (rw *ResponseWriter) Write(p []byte) (int, error) {
	compressionMethod, acceptCompressed := rw.requestData.AcceptCompressed()
	if rw.headerWritten && acceptCompressed {
		switch *compressionMethod {
		case CompressionMethodGZip:
			gw := gzip.NewWriter(rw.w)
			defer func(gw *gzip.Writer) {
				err := gw.Close()
				if err != nil {
					system.Error(err)
				}
			}(gw)
			return gw.Write(p)
		}

	}
	return rw.w.Write(p)
}
