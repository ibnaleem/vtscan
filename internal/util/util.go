package util

import (
	"os"
	"io"
	"fmt"
	"regexp"
	"crypto/sha256"
)

type Theme struct {
	Reset     string // Reset formatting
	Bold      string // Bold text
	Underline string // Underlined text
	Red       string // Red text
	Green     string // Green text
	Yellow    string // Yellow text
	Blue      string // Blue text
	Magenta   string // Magenta text
	Cyan      string // Cyan text
	White     string // White text
	Gray      string // Gray text
}

// LightTheme defines colors optimized for light terminal backgrounds.
var LightTheme = Theme{
	Reset:     "\033[0m",
	Bold:      "\033[1m",
	Underline: "\033[4m",
	Red:       "\033[31m", // Bright red for light background
	Green:     "\033[32m", // Forest green
	Yellow:    "\033[33m", // Dark yellow
	Blue:      "\033[34m", // Navy blue
	Magenta:   "\033[35m", // Dark magenta
	Cyan:      "\033[36m", // Dark cyan
	White:     "\033[37m", // Black for light background
	Gray:      "\033[90m", // Dark gray
}

// DarkTheme defines colors optimized for dark terminal backgrounds.
var DarkTheme = Theme{
	Reset:     "\033[0m",
	Bold:      "\033[1m",
	Underline: "\033[4m",
	Red:       "\033[91m", // Light red for dark background
	Green:     "\033[92m", // Light green
	Yellow:    "\033[93m", // Bright yellow
	Blue:      "\033[94m", // Light blue
	Magenta:   "\033[95m", // Light magenta
	Cyan:      "\033[96m", // Light cyan
	White:     "\033[97m", // White for dark background
	Gray:      "\033[37m", // Light gray
}

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