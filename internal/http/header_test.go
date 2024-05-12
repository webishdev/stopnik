package http

import (
	"stopnik/assert"
	"testing"
)

func Test_HTTPHeaders(t *testing.T) {
	assert.Equal(t, Location, "Location")
	assert.Equal(t, ContentType, "Content-Type")
	assert.Equal(t, Authorization, "Authorization")
	assert.Equal(t, AuthBasic, "Basic")
	assert.Equal(t, AuthBearer, "Bearer")
	assert.Equal(t, ContentTypeJSON, "application/json")
}
