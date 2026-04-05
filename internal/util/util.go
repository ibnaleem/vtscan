package util

import (
	"os"
	"io"
	"fmt"
	"regexp"
	"crypto/sha256"
)

func CheckError(err error) {
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}

func CheckHash(input string) bool {
	md5    := regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
	sha1   := regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	sha256 := regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

	return md5.MatchString(input) || sha1.MatchString(input) || sha256.MatchString(input)
}

func CalculateFileSHA256Hash(path string) (string, error) {

	f, err := os.OpenFile(path, os.O_RDONLY, 0644)

	if err != nil {
		return "", err
	}

	defer f.Close()

	sha256Hasher := sha256.New()

	_, err = io.Copy(sha256Hasher, f)

	if err != nil {
		return "", err
	}

	hash := sha256Hasher.Sum(nil)

	return fmt.Sprintf("%x", hash), nil

}