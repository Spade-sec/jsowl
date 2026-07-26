package main

import (
	"fmt"
	"os"
)

func main() {
	if err := newRootCommand(dependencies{}).Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "jsowl:", err)
		os.Exit(1)
	}
}
