// Command jsowl-mcp serves JsOwl as an MCP server over stdio, letting LLM
// clients scan targets and query API endpoints and sensitive findings.
//
// Configure it in an MCP client with:
//
//	{
//	  "mcpServers": {
//	    "jsowl": {
//	      "command": "/path/to/jsowl-mcp",
//	      "args": ["-dir", "/path/to/jsowl-reports", "-config", "/path/to/config.yml"]
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

	"github.com/youmulijiang/jsowl"
	"github.com/youmulijiang/jsowl/mcpserver"
)

func main() {
	dir := flag.String("dir", "", "directory that receives per-scan report files (default: per-process temp directory)")
	configPath := flag.String("config", "", "YAML configuration file used as the base scan configuration (proxy, browser, scope, rules; per-scan tool inputs override mode, headers, and timeout)")
	flag.Parse()

	var base *jsowl.Config
	if *configPath != "" {
		loaded, err := jsowl.LoadConfig(*configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "jsowl-mcp: load config:", err)
			os.Exit(1)
		}
		base = &loaded
	}

	store := mcpserver.NewStore(*dir, base)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := store.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "jsowl-mcp:", err)
		os.Exit(1)
	}
}
