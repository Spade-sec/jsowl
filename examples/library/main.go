// Command library demonstrates JsOwl's reusable Go API.
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/youmulijiang/jsowl"
)

func main() {
	config := jsowl.DefaultConfig()
	config.Mode = jsowl.ModeAuto
	config.Output.DownloadJS = false

	scanner, err := jsowl.New(config)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx, jsowl.Target{URL: "https://example.com"})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s: %d findings\n", result.Target, result.Statistics.Findings)

	targets := []jsowl.Target{
		{URL: "https://example.com"},
		{URL: "https://example.org"},
	}
	for item := range scanner.ScanBatch(ctx, targets) {
		if item.Err != nil {
			log.Printf("%s: %v", item.Target.URL, item.Err)
			continue
		}
		fmt.Printf("%s: %d resources\n",
			item.Result.Target, item.Result.Statistics.Resources)
	}
}
