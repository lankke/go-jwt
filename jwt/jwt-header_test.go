package jwt

import "testing"

func TestCreateJwtHeaderUnsupportedAlgorithm(t *testing.T) {
	_, err := CreateJwtHeader("unsupported_alg")
	if err == nil {
		t.Errorf("expected error for unsupported algorithm, got nil")
	}
}
