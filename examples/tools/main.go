// Command library-tools demonstrates driving JsOwl from another Go program
// through the tools package: first a typed call, then a raw JSON dispatch
// round trip — the same envelope a foreign-language host would send.
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/youmulijiang/jsowl/tools"
)

func main() {
	store := tools.NewStore("")

	// Typed call.
	scan, err := store.Scan(context.Background(), tools.ScanInput{
		URL:  "https://example.com",
		Mode: "direct",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("typed scan: id=%s endpoints=%d routes=%d sensitive=%d\n",
		scan.ScanID, scan.Endpoints, scan.Routes, scan.Sensitive)

	endpoints, err := store.Endpoints(tools.EndpointsInput{
		ScanID: scan.ScanID, Type: "api", Limit: 5,
	})
	if err != nil {
		log.Fatal(err)
	}
	for _, row := range endpoints {
		fmt.Printf("  %s %s\n", row.Method, row.URL)
	}

	// JSON dispatch (the wire format other tools can use).
	requests := []string{
		`{"tool":"endpoints","arguments":{"scan_id":"` + scan.ScanID + `","type":"route","limit":5}}`,
		`{"tool":"sensitive","arguments":{"scan_id":"` + scan.ScanID + `","min_severity":"high"}}`,
		`{"tool":"scans"}`,
		`{"tool":"nope"}`,
	}
	for _, request := range requests {
		fmt.Printf("dispatch %s\n=> %s\n", request, store.Dispatch(context.Background(), []byte(request)))
	}
}
