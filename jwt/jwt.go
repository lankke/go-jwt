package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

const (
	AlgHS256 = "HS256"
	AlgHS384 = "HS384"
)

type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

func (j JWTHeader) String() string {
	return fmt.Sprintf(`{"alg":"%s","typ":"%s"}`, j.Alg, j.Typ)
}

func (j JWTHeader) Base64() string {
	return base64.URLEncoding.EncodeToString([]byte(j.String()))
}

func isSupportedAlgorithm(alg string) bool {
	return alg == AlgHS256 || alg == AlgHS384
}

func CreateJwtHeader(alg string) (JWTHeader, error) {

	if !isSupportedAlgorithm(alg) {
		return JWTHeader{}, fmt.Errorf("unsupported algorithm")
	}

	return JWTHeader{
		Alg: alg,
		Typ: "JWT",
	}, nil
}

func CreateJwt(secret string, body []byte) string {

	header, _ := CreateJwtHeader("HS256")

	bodyBase64 := base64.URLEncoding.EncodeToString(body)

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(fmt.Sprintf("%s.%s", header.Base64(), bodyBase64)))
	signature := base64.URLEncoding.EncodeToString(h.Sum(nil))

	return fmt.Sprintf("%s.%s.%s", header.Base64(), bodyBase64, signature)
}
