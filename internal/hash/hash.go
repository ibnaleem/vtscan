package hash

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"regexp"
)

func CheckHash(input string) bool {
	md5    := regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	sha1   := regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	sha256 := regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

	return md5.MatchString(input) || sha1.MatchString(input) || sha256.MatchString(input)
}

func CalculateFileSHA256(path string) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0644)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err = io.Copy(hasher, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}
