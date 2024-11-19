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

	t.Run("supports HS256 algorithm", func(t *testing.T) {

		header, err := CreateJwtHeader("HS256")

		assert.NoError(t, err)
		assert.NotEmpty(t, header)

	})

	t.Run("supports HS384 algorithm", func(t *testing.T) {

		header, err := CreateJwtHeader("HS384")

		assert.NoError(t, err)
		assert.NotEmpty(t, header)

	})
}
