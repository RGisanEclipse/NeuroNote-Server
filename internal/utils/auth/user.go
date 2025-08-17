package auth

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"
)

const charset = "abcdefghijklmnopqrstuvwxyz0123456789"

func randomString(length int) string {
	b := make([]byte, length)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

func GenerateUserId() string{

	timestampBase36 := fmt.Sprintf("%x", time.Now().UnixNano()/1e6)

	remaining := 14 - len(timestampBase36)
	if remaining < 0 {
		remaining = 0
	}

	return timestampBase36 + randomString(remaining)
}