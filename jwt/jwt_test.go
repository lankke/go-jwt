package jwt

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateJwt(t *testing.T) {
	expectedHeader := `{"alg":"HS256","typ":"JWT"}`
	expectedBody := `{"name":"Test","age":32}`
	expectedSignature := `signature`
	// Create a new JWT
	jwt := CreateJwt([]byte(expectedBody))

	t.Run("Returns a string", func(t *testing.T) {
		assert.NotEmpty(t, jwt)
	})

	t.Run("jwt contains two dots", func(t *testing.T) {
		expectedDotCount := 2
		dotCount := strings.Count(jwt, ".")

		assert.Equal(t, expectedDotCount, dotCount)
	})

	t.Run("jwt split by dots contains 3 parts", func(t *testing.T) {
		expectedPartCount := 3
		parts := strings.Split(jwt, ".")

		assert.Equal(t, expectedPartCount, len(parts))
	})

	t.Run("jwt parts are not empty", func(t *testing.T) {
		parts := strings.Split(jwt, ".")
		for _, part := range parts {
			assert.NotEmpty(t, part)
		}
	})

	t.Run("header is base64 encoded", func(t *testing.T) {
		parts := strings.Split(jwt, ".")
		header := parts[0]

		decodedHeader, err := base64.URLEncoding.DecodeString(header)
		assert.NoError(t, err)
		assert.Equal(t, expectedHeader, string(decodedHeader))
	})

	t.Run("header is json", func(t *testing.T) {
		parts := strings.Split(jwt, ".")
		header := parts[0]

		decodedHeader, err := base64.URLEncoding.DecodeString(header)
		assert.NoError(t, err)
		assert.JSONEq(t, `{ "alg": "HS256","typ": "JWT"}`, string(decodedHeader))
	})

	t.Run("body is base64 encoded", func(t *testing.T) {
		parts := strings.Split(jwt, ".")
		body := parts[1]

		decodedBody, err := base64.URLEncoding.DecodeString(body)

		fmt.Println(string(decodedBody))

		assert.NoError(t, err)
		assert.NotEmpty(t, decodedBody)
		assert.JSONEq(t, expectedBody, string(decodedBody))
	})

	t.Run("signature is base64 encoded", func(t *testing.T) {
		parts := strings.Split(jwt, ".")
		signature := parts[2]

		decodedSignature, err := base64.URLEncoding.DecodeString(signature)
		assert.NoError(t, err)
		assert.Equal(t, expectedSignature, string(decodedSignature))
	})

}
