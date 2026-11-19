package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const MaxLength = 128

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", fmt.Errorf("password must not exceed %d characters", MaxLength)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	derivedKey := argon2.IDKey([]byte(password), salt, 2, 19*1024, 1, 32)
	argonHash := argon2idHash{
		version: argon2.Version,
		derivedKey: derivedKey,
		salt: salt,
		iterations: 2,
		memoryKiB: 19*1024,
		parallelism: 1,
	}
	return encodeArgon2idHash(argonHash), nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}
	expectedHash, ok := decodeLegacyHash(encodedHash)
	if ok {
		candidateHash := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(candidateHash[:], expectedHash) == 1
	}
	parsedArgon, ok := parseArgon2idHash(encodedHash)
	if !ok || parsedArgon.version != argon2.Version {
		return false
	}
	key := argon2.IDKey([]byte(password), parsedArgon.salt, parsedArgon.iterations, parsedArgon.memoryKiB, parsedArgon.parallelism, uint32(len(parsedArgon.derivedKey)))
	return subtle.ConstantTimeCompare(key, parsedArgon.derivedKey) == 1
}

func NeedsRehash(string) bool {
	return false
}
