(() => {
  "use strict";

  if (window.__jsowlCollector) return;

  const resourceURLs = new Set();
  const add = (candidate) => {
    if (!candidate) return;
    let value = candidate;
    if (candidate instanceof Request) value = candidate.url;
    if (candidate instanceof URL) value = candidate.href;
    if (typeof value !== "string") return;
    try {
      resourceURLs.add(new URL(value, document.baseURI).href);
    } catch (_) {
      // Invalid and non-URL values are intentionally ignored.
    }
  };

  const collectDOM = (root) => {
    if (!root || !root.querySelectorAll) return;
    if (root.matches && root.matches("[src], [href]")) {
      add(root.getAttribute("src") || root.getAttribute("href"));
    }
    root.querySelectorAll("[src], [href]").forEach((element) => {
      add(element.getAttribute("src") || element.getAttribute("href"));
    });
  };

  const originalFetch = window.fetch;
  if (typeof originalFetch === "function") {
    window.fetch = function(input) {
      add(input);
      return originalFetch.apply(this, arguments);
    };
  }

  const originalOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, requestURL) {
    add(requestURL);
    return originalOpen.apply(this, arguments);
  };

  const startObservers = () => {
    collectDOM(document);
    try {
      performance.getEntriesByType("resource").forEach((entry) => add(entry.name));
    } catch (_) {
      // Performance entries are an enhancement and may be unavailable.
    }
    new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === "attributes") {
          add(mutation.target.getAttribute(mutation.attributeName));
        }
        mutation.addedNodes.forEach(collectDOM);
      });
    }).observe(document.documentElement, {
      subtree: true,
      childList: true,
      attributes: true,
      attributeFilter: ["src", "href"],
    });
  };

  window.__jsowlCollector = {
    snapshot() {
      collectDOM(document);
      try {
        performance.getEntriesByType("resource").forEach((entry) => add(entry.name));
      } catch (_) {}
      return Array.from(resourceURLs).sort();
    },
  };

  if (document.documentElement) startObservers();
  else document.addEventListener("DOMContentLoaded", startObservers, { once: true });
})();
