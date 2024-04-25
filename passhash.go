package passhash

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	pbkdf2lib "golang.org/x/crypto/pbkdf2"
)

var src = rand.NewSource(time.Now().UnixNano())

const (
	randomSize       = 24
	iterationDefault = 25000
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func getRandomString(n int) string {
	sb := strings.Builder{}
	sb.Grow(n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			sb.WriteByte(letterBytes[idx])
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return sb.String()
}

func b64Decode(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, ".", "+")
	return base64.RawStdEncoding.DecodeString(s)
}

func b64Encode(b []byte) string {
	s := base64.RawStdEncoding.EncodeToString(b)
	return strings.ReplaceAll(s, "+", ".")
}

func MakePassword(password string, iteration int, salt string) (string, error) {
	if len(password) == 0 {
		return "", fmt.Errorf("password cannot be empty")
	}
	if iteration == 0 {
		iteration = iterationDefault
	}
	saltb := []byte(salt)
	if len(salt) == 0 {
		saltb = []byte(getRandomString(randomSize))
	}
	key := pbkdf2lib.Key([]byte(password), saltb, iteration, sha512.Size, sha512.New)
	return fmt.Sprintf("$pbkdf2-sha512$%d$%s$%s", iteration, b64Encode(saltb), b64Encode(key)), nil
}

func CheckPassword(password string, passwordHash string) bool {
	tokens := strings.Split(passwordHash, "$")
	iteration, err := strconv.Atoi(tokens[2])
	if err != nil {
		fmt.Printf("Failed to convert iteration to integer: %s", err)
	}
	salt, err := b64Decode(tokens[3])
	if err != nil {
		fmt.Printf("Failed to base64 decode the salt: %s", err)
	}
	passwordHashInDatabase, err := b64Decode(tokens[4])
	if err != nil {
		fmt.Printf("Failed to base64 decode password hash from the database: %s", err)
	}

	key := pbkdf2lib.Key([]byte(password), salt, iteration, sha512.Size, sha512.New)
	return bytes.Equal(key, passwordHashInDatabase)
}
