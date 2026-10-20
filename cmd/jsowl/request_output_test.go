package main

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/youmulijiang/jsowl"
)

func TestRequestPrinterConcurrentProducersAndDrain(t *testing.T) {
	var output bytes.Buffer
	events := make(chan jsowl.RequestEvent, 4)
	done := startRequestPrinter(&output, events, false)
	var workers sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		workers.Add(1)
		go func(id int) {
			defer workers.Done()
			for n := 0; n < 100; n++ {
				events <- jsowl.RequestEvent{Method: "GET", URL: fmt.Sprintf("http://test/%d/%d", id, n), Success: true, StatusCode: 200, Size: 42}
			}
		}(worker)
	}
	workers.Wait()
	close(events)
	<-done
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	seen := make(map[string]bool)
	for _, line := range lines {
		if !strings.HasPrefix(line, "[GET] [http://test/") || !strings.HasSuffix(line, "] [success] [200] [42]") || seen[line] {
			t.Fatalf("corrupt or duplicate line: %q", line)
		}
		seen[line] = true
	}
	if len(seen) != 1600 {
		t.Fatalf("received %d/1600 lines", len(seen))
	}
}

func TestRequestPrinterPreservesQueueOrder(t *testing.T) {
	var output bytes.Buffer
	events := make(chan jsowl.RequestEvent, 2)
	events <- jsowl.RequestEvent{Method: "POST", URL: "http://test/first", Success: true, StatusCode: 500, Size: 12}
	events <- jsowl.RequestEvent{URL: "http://test/second"}
	close(events)
	<-startRequestPrinter(&output, events, false)
	want := "[POST] [http://test/first] [success] [500] [12]\n[GET] [http://test/second] [faile] [0] [0]\n"
	if output.String() != want {
		t.Fatalf("output = %q", output.String())
	}
}
