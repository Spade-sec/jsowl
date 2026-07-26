package ua

import (
	"encoding/binary"
	"io"
	"net/http"
)

var desktop = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:142.0) Gecko/20100101 Firefox/142.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
}

// ForTarget resolves header and configured overrides before selecting a random desktop UA.
func ForTarget(configured string, headers http.Header, random io.Reader) (string, error) {
	if value := headers.Get("User-Agent"); value != "" {
		return value, nil
	}
	if configured != "" {
		return configured, nil
	}
	var selection [2]byte
	if _, err := io.ReadFull(random, selection[:]); err != nil {
		return "", err
	}
	index := int(binary.LittleEndian.Uint16(selection[:])) % len(desktop)
	return desktop[index], nil
}
