package util

import (
	"os"
	"fmt"
	"regexp"
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