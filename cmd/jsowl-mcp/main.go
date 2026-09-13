// Command jsowl-mcp serves JsOwl as an MCP server over stdio, letting LLM
// clients scan targets and query API endpoints and sensitive findings.
//
// Configure it in an MCP client with:
//
//	{
//	  "mcpServers": {
//	    "jsowl": {
//	      "command": "/path/to/jsowl-mcp",
//	      "args": ["-dir", "/path/to/jsowl-reports"]
//	    }
//	  }
//	}
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/youmulijiang/jsowl/internal/mcpserver"
)

func main() {
	dir := flag.String("dir", "", "directory that receives per-scan report files (default: per-process temp directory)")
	flag.Parse()

	store := mcpserver.NewStore(*dir)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := store.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "jsowl-mcp:", err)
		os.Exit(1)
	}
}
