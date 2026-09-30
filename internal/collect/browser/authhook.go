package browser

import (
	"encoding/json"
	"net/http"
	"strings"
)

// browserManagedHeaders are headers the browser transport already controls:
// replaying them from a page script would duplicate or corrupt the request.
var browserManagedHeaders = []string{
	"Cookie", "User-Agent", "Host", "Content-Length", "Connection",
	"Referer", "Origin", "Accept-Encoding", "Sec-Fetch-Dest",
	"Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User", "Sec-Ch-Ua",
	"Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
}

// storageKeysForToken are the storage keys token-based SPAs most commonly
// read their session token from. A Bearer credential is seeded into each
// missing key so an app that lost its login state (fresh headless profile)
// can still authenticate from its own logic.
var storageKeysForToken = []string{
	"token", "Token", "access_token", "accessToken", "auth_token",
	"authToken", "jwt", "Authorization", "authorization",
}

// authHookScript builds a document-start script that forces user-supplied
// headers onto same-origin fetch/XHR requests, and seeds Bearer tokens into
// common storage keys.
//
// It is a fallback for token-based SPAs whose credential lives in
// localStorage rather than a cookie, where cookie injection alone cannot
// restore the session. Replay is override semantics: a value from -H
// replaces whatever the page attached for the same header, so the flag stays
// the single source of truth for credentials. The script runs with
// DisableInjection too: it carries the user's credentials, not collector
// observation.
func authHookScript(origin string, headers http.Header) string {
	replay := make(http.Header)
	for name, values := range headers {
		if containsFold(browserManagedHeaders, name) {
			continue
		}
		replay[textCanonical(name)] = values
	}
	if len(replay) == 0 {
		return ""
	}
	bearer := bearerToken(replay.Get("Authorization"))
	config, err := json.Marshal(authHookConfig{
		Headers: map[string][]string(replay),
		Origin:  origin,
		Bearer:  bearer,
	})
	if err != nil {
		return ""
	}
	return `(function(){
var CONFIG = ` + string(config) + `;` + authHookBody(storageKeysForToken) + `})();`
}

// authHookConfig is the JSON payload embedded into the generated script.
// Pure JSON keeps the literal valid both as a JavaScript expression and for
// tests that decode it back.
type authHookConfig struct {
	Headers map[string][]string `json:"headers"`
	Origin  string              `json:"origin"`
	Bearer  string              `json:"bearer"`
}

func authHookBody(storageKeys []string) string {
	return `
function sameOrigin(url) {
  try { return new URL(url, location.href).origin === CONFIG.origin; }
  catch (e) { return false; }
}
function valuesOf(name) {
  return CONFIG.headers[name] || CONFIG.headers[name.toLowerCase()] || [];
}
function replayNames() {
  var names = {};
  for (var name in CONFIG.headers) { names[name.toLowerCase()] = true; }
  return names;
}
if (CONFIG.bearer) {
  try {
    for (var store of [window.localStorage, window.sessionStorage]) {
      for (var key of ` + marshalStrings(storageKeys) + `) {
        if (store.getItem(key) === null) { store.setItem(key, CONFIG.bearer); }
      }
    }
  } catch (e) {}
}
if (window.fetch) {
  var nativeFetch = window.fetch;
  window.fetch = function (input, init) {
    try {
      var url = typeof input === 'string' ? input :
        (input && input.url) || '';
      if (sameOrigin(url)) {
        init = init || {};
        var base = init.headers ||
          (input && typeof input !== 'string' && input.headers) || null;
        var provided = new Headers(base);
        // -H wins: set() replaces any value the page attached for the same
        // header instead of appending a second one.
        for (var name in CONFIG.headers) {
          valuesOf(name).forEach(function (value) {
            provided.set(name, value);
          });
        }
        init.headers = provided;
      }
    } catch (e) {}
    return nativeFetch.call(this, input, init);
  };
}
if (window.XMLHttpRequest) {
  var replayed = replayNames();
  var nativeOpen = XMLHttpRequest.prototype.open;
  var nativeSet = XMLHttpRequest.prototype.setRequestHeader;
  var nativeSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function () {
    this.__jsowlAuth = { url: arguments[1] || '' };
    return nativeOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.setRequestHeader = function (name, value) {
    // setRequestHeader appends rather than replaces, so a page value for a
    // replayed header must be swallowed here; otherwise the request would
    // carry "page value, -H value" and the credential would be polluted.
    if (this.__jsowlAuth && name && replayed[name.toLowerCase()]) {
      return;
    }
    return nativeSet.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function () {
    try {
      if (this.__jsowlAuth && sameOrigin(this.__jsowlAuth.url)) {
        for (var name in CONFIG.headers) {
          valuesOf(name).forEach(function (value) {
            nativeSet.call(this, name, value);
          });
        }
      }
    } catch (e) {}
    return nativeSend.apply(this, arguments);
  };
}
})();`
}

// bearerToken extracts the credential from an "Authorization: Bearer x"
// header so it can be seeded into storage keys.
func bearerToken(value string) string {
	value = strings.TrimSpace(value)
	const scheme = "Bearer "
	if len(value) > len(scheme) && strings.EqualFold(value[:len(scheme)], scheme) {
		return strings.TrimSpace(value[len(scheme):])
	}
	return ""
}

// marshalStrings encodes a string slice as a JSON array literal, falling back
// to an empty array so the generated script never contains bare nil.
func marshalStrings(values []string) string {
	encoded, err := json.Marshal(values)
	if err != nil {
		return "[]"
	}
	return string(encoded)
}

// jsonEncodeJS encodes one string as a JSON literal, which is valid inside a
// JavaScript expression.
func jsonEncodeJS(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "''"
	}
	return string(encoded)
}

// textCanonical canonicalizes a header name the way net/http does so the
// generated script's lookups match Go's serialization.
func textCanonical(name string) string {
	return http.CanonicalHeaderKey(name)
}
