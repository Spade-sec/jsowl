// Package extract discovers hosts (domains, IP addresses and internal-host
// candidates) in JavaScript and other content the scan already downloaded, and
// normalizes the hosts the scan itself touched with the same rules.
//
// What it does:
//   - extracts candidates from AST string literals, statically folded
//     expressions, network URLs and a bounded regex fallback;
//   - normalizes them with net/netip, net/url and golang.org/x/net/idna;
//   - splits domain names with a Public Suffix List snapshot shipped in the
//     binary, so the scan needs no network access;
//   - deduplicates by kind + normalized value while keeping every piece of
//     source evidence.
//
// What it never does:
//   - it does not execute target JavaScript, and never evaluates functions,
//     getters, eval or dynamic expressions;
//   - it does not resolve or probe anything: no DNS query, no HTTP request is
//     made for extraction;
//   - it does not claim reachability. A discovered host is a value found in
//     the analyzed code, not a confirmed accessible asset;
//   - it produces no numeric confidence or risk score. Evidence strength is
//     expressed only by the documented extraction method.
package extract
