package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func createExpectedSignature(header, body, secret string) string {

	bodyBase64 := base64.URLEncoding.EncodeToString([]byte(body))

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(fmt.Sprintf("%s.%s", header, bodyBase64)))
	signature := base64.URLEncoding.EncodeToString(h.Sum(nil))
	return signature
}

func TestCreateJwt(t *testing.T) {
	expectedHeader := CreateJwtHeader()
	expectedBody := `{"name":"Test","age":32}`

	sharedSecret := "this_is_a_secret"

	expectedSignature := createExpectedSignature(expectedHeader.Base64(), expectedBody, sharedSecret)
	// Create a new JWT
	jwt := CreateJwt(sharedSecret, []byte(expectedBody))

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
		assert.Equal(t, expectedHeader.String(), string(decodedHeader))
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

		assert.Equal(t, expectedSignature, signature)
	})

}
