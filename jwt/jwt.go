package jwt

import (
	"encoding/base64"
	"fmt"
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

func CreateJwtHeader() JWTHeader {
	return JWTHeader{
		Alg: "HS256",
		Typ: "JWT",
	}
}

func CreateJwt(body []byte) string {

	header := CreateJwtHeader()

	bodyBase64 := base64.URLEncoding.EncodeToString(body)
	signature := base64.URLEncoding.EncodeToString([]byte(`signature`))

	return fmt.Sprintf("%s.%s.%s", header.Base64(), bodyBase64, signature)
}
