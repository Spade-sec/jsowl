// Command jsowl-mcp serves JsOwl as an MCP server, letting LLM clients scan
// targets and query API endpoints and sensitive findings. By default it
// speaks MCP over stdio; pass -listen to expose it over HTTP instead.
//
// Configure it in an MCP client over stdio with:
//
//	{
//	  "mcpServers": {
//	    "jsowl": {
//	      "command": "/path/to/jsowl-mcp",
//	      "args": ["-dir", "/path/to/jsowl-reports", "-c", "/path/to/config.yml"]
//	    }
//	  }
//	}
//
// Or run it as a shared HTTP server:
//
//	jsowl-mcp -listen 127.0.0.1:8080 -c config.yml
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/pflag"

	"github.com/youmulijiang/jsowl"
	"github.com/youmulijiang/jsowl/mcpserver"
)

func main() {
	flags := pflag.NewFlagSet("jsowl-mcp", pflag.ContinueOnError)
	dir := flags.StringP("dir", "d", "", "directory that receives per-scan report files (default: per-process temp directory)")
	configPath := flags.StringP("config", "c", "", "YAML configuration file used as the base scan configuration (proxy, browser, scope, rules; per-scan tool inputs override mode, headers, and timeout)")
	listen := flags.String("listen", "", "listen address (ip:port, e.g. 127.0.0.1:8080) to serve MCP over streamable HTTP instead of stdio")
	if err := flags.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "jsowl-mcp:", err)
		os.Exit(2)
	}

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
	var err error
	if *listen != "" {
		err = store.RunHTTP(ctx, *listen)
	} else {
		err = store.Run(ctx)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "jsowl-mcp:", err)
		os.Exit(1)
	}
}
