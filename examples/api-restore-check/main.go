package main

import (
 "encoding/json"
 "fmt"
 "net/url"
 "os"
 "path/filepath"

 "github.com/youmulijiang/jsowl/internal/discover"
)

func main() {
 files, err := filepath.Glob("testdata/api-restore-counterexamples/*.js")
 if err != nil { panic(err) }
 source, _ := url.Parse("file:///api-restore-check.js")
 for _, file := range files {
  body, err := os.ReadFile(file)
  if err != nil { panic(err) }
  candidates := discover.APIFromAST(source, body)
  raw := make([]string, 0, len(candidates))
  for _, candidate := range candidates { raw = append(raw, candidate.Raw) }
  encoded, _ := json.Marshal(raw)
  fmt.Printf("%s\t%s\n", filepath.Base(file), encoded)
 }
}

