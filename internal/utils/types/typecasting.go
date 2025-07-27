package types

import (
	"fmt"	
	"strconv"
)

func ConvertStringToUint(s string) (uint, error) {
	parsed, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid uint format: %w", err)
	}
	return uint(parsed), nil
}

func ConvertUintToString(i uint) string {
	return strconv.FormatUint(uint64(i), 10)
}