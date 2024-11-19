package jwt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateJwtHeader(t *testing.T) {

	t.Run("expect error when algorithm unsupported", func(t *testing.T) {

		header, err := CreateJwtHeader("GIBBERISH")

		assert.Error(t, err)
		assert.Empty(t, header)

	})
}
