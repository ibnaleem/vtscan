package util

import (
	"os"
	"fmt"
)

func CheckError(err error) {
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}