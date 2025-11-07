package vault

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewPasswordHasher(t *testing.T) {
	ph := NewArgon2PasswordHasher()
	assert.NotNil(t, ph)
	assert.Equal(t, uint32(1), ph.time)
	assert.Equal(t, uint32(64*1024), ph.memory)
	assert.Equal(t, uint8(4), ph.threads)
	assert.Equal(t, uint32(32), ph.keyLen)
}

func TestNewPasswordHasherCustom(t *testing.T) {
	ph := NewArgon2PasswordHasherCustom(2, 128*1024, 8, 64)
	assert.NotNil(t, ph)
	assert.Equal(t, uint32(2), ph.time)
	assert.Equal(t, uint32(128*1024), ph.memory)
	assert.Equal(t, uint8(8), ph.threads)
	assert.Equal(t, uint32(64), ph.keyLen)
}

func TestPasswordHasher_Hash_Valid(t *testing.T) {
	ph := NewArgon2PasswordHasher()

	password := "my-secure-password-123"
	hash, err := ph.Hash(password)

	assert.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.Contains(t, hash, "$argon2id$")
}

func TestPasswordHasher_Hash_Empty(t *testing.T) {
	ph := NewArgon2PasswordHasher()

	hash, err := ph.Hash("")
	assert.Error(t, err)
	assert.Empty(t, hash)
}

func TestPasswordHasher_Hash_TooLong(t *testing.T) {
	ph := NewArgon2PasswordHasher()

	password := string(make([]byte, 100))
	hash, err := ph.Hash(password)

	assert.Error(t, err)
	assert.Empty(t, hash)
}

func TestPasswordHasher_Hash_Uniqueness(t *testing.T) {
	ph := NewArgon2PasswordHasher()

	password := "my-password"
	hash1, err := ph.Hash(password)
	assert.NoError(t, err)

	hash2, err := ph.Hash(password)
	assert.NoError(t, err)

	// Hashes should be different due to random salt
	assert.NotEqual(t, hash1, hash2)
}

func TestPasswordHasher_Verify_Valid(t *testing.T) {
	ph := NewArgon2PasswordHasher()

	password := "my-secure-password-123"
	hash, err := ph.Hash(password)
	assert.NoError(t, err)

	verified, err := ph.Verify(password, hash)
	assert.NoError(t, err)
	assert.True(t, verified)
}

func TestPasswordHasher_Verify_Invalid(t *testing.T) {
	ph := NewArgon2PasswordHasher()

	password := "my-secure-password-123"
	hash, err := ph.Hash(password)
	assert.NoError(t, err)

	verified, err := ph.Verify("wrong-password", hash)
	assert.NoError(t, err)
	assert.False(t, verified)
}

func TestPasswordHasher_Verify_Empty(t *testing.T) {
	ph := NewArgon2PasswordHasher()

	verified, err := ph.Verify("", "")
	assert.Error(t, err)
	assert.False(t, verified)
}

func TestPasswordHasher_Verify_EmptyPassword(t *testing.T) {
	ph := NewArgon2PasswordHasher()

	password := "my-password"
	hash, err := ph.Hash(password)
	assert.NoError(t, err)

	verified, err := ph.Verify("", hash)
	assert.Error(t, err)
	assert.False(t, verified)
}

func TestPasswordHasher_Verify_InvalidHash(t *testing.T) {
	ph := NewArgon2PasswordHasher()

	verified, err := ph.Verify("password", "invalid-hash")
	assert.Error(t, err)
	assert.False(t, verified)
}

func TestPasswordHasher_Hash_DifferentPasswords(t *testing.T) {
	ph := NewArgon2PasswordHasher()

	password1 := "password1"
	password2 := "password2"

	hash1, err := ph.Hash(password1)
	assert.NoError(t, err)

	hash2, err := ph.Hash(password2)
	assert.NoError(t, err)

	// Verify password1 with hash1
	verified1, err := ph.Verify(password1, hash1)
	assert.NoError(t, err)
	assert.True(t, verified1)

	// Verify password1 with hash2 should fail
	verified2, err := ph.Verify(password1, hash2)
	assert.NoError(t, err)
	assert.False(t, verified2)
}

func TestConstantTimeCompare(t *testing.T) {
	a := []byte("hello")
	b := []byte("hello")
	c := []byte("world")

	assert.True(t, constantTimeCompare(a, b))
	assert.False(t, constantTimeCompare(a, c))
	assert.False(t, constantTimeCompare(a, []byte("hi")))
}

func TestPasswordHasher_RealWorldScenario(t *testing.T) {
	ph := NewArgon2PasswordHasher()

	// Simulate user registration
	password := "MySecureP@ssw0rd!"
	hash, err := ph.Hash(password)
	assert.NoError(t, err)
	assert.NotEmpty(t, hash)

	// Simulate user login with correct password
	verified, err := ph.Verify(password, hash)
	assert.NoError(t, err)
	assert.True(t, verified)

	// Simulate user login with wrong password
	verified, err = ph.Verify("WrongP@ssw0rd!", hash)
	assert.NoError(t, err)
	assert.False(t, verified)
}
