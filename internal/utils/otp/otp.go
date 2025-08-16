package otp

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func GenerateOTP() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(10000))
	return fmt.Sprintf("%04d", n.Int64())
}