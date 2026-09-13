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

  // ---- framework route collection ----

  const routes = new Map();
  const addRoute = (candidate, name, source) => {
    if (!candidate || typeof candidate !== "string" || candidate.length > 500) return;
    try {
      const resolved = new URL(candidate, document.baseURI);
      if (resolved.origin !== window.location.origin) return;
      const key = resolved.pathname + resolved.search;
      if (!routes.has(key)) routes.set(key, { path: key, name: name || "", source });
    } catch (_) {
      // Non-relative or invalid paths are intentionally ignored.
    }
  };

  const recordLocation = (source) => {
    addRoute(window.location.pathname + window.location.search, "", source);
    if (window.location.hash.length > 1) {
      addRoute(window.location.hash.slice(1), "", source + "-hash");
    }
  };

  ["pushState", "replaceState"].forEach((methodName) => {
    const original = history[methodName];
    if (typeof original !== "function") return;
    history[methodName] = function() {
      recordLocation("history-hook");
      return original.apply(this, arguments);
    };
  });
  window.addEventListener("popstate", () => recordLocation("history-hook"));
  window.addEventListener("hashchange", () => recordLocation("history-hook"));

  const collectAnchors = (root) => {
    if (!root || !root.querySelectorAll) return;
    const scan = (element) => {
      if (element.matches && element.matches("a[href]")) {
        addRoute(element.getAttribute("href"), "", "dom");
      }
      element.querySelectorAll("a[href]").forEach((anchor) => {
        addRoute(anchor.getAttribute("href"), "", "dom");
      });
    };
    scan(root);
  };

  const joinRoutePaths = (parent, child) => {
    if (!child) return parent;
    if (child.startsWith("/")) return child;
    if (!parent) return "/" + child;
    return parent.replace(/\/+$/, "") + "/" + child;
  };

  const walkRouteConfig = (config, prefix) => {
    (config || []).forEach((record) => {
      if (!record || typeof record !== "object") return;
      const full = joinRoutePaths(prefix, record.path);
      if (record.path !== undefined) addRoute(full, record.name, "vue");
      if (Array.isArray(record.children)) walkRouteConfig(record.children, full);
    });
  };

  const collectVueRoutes = () => {
    const roots = document.querySelectorAll(
      "#app, #root, [data-v-app], [id], body > div",
    );
    roots.forEach((element) => {
      try {
        // Vue 2: instance root carries $router with the static route config.
        const vue2 = element.__vue__;
        const vue2Router = vue2 && vue2.$router;
        if (vue2Router && Array.isArray(vue2Router.options)) {
          walkRouteConfig(vue2Router.options.routes, "");
        } else if (vue2Router && vue2Router.options && vue2Router.options.routes) {
          walkRouteConfig(vue2Router.options.routes, "");
        }
        // Vue 3: app context exposes the router; getRoutes() returns the
        // flattened, normalized route table.
        const app = element.__vue_app__;
        const router = app && app._context && app._context.config &&
          app._context.config.globalProperties &&
          app._context.config.globalProperties.$router;
        if (router && typeof router.getRoutes === "function") {
          router.getRoutes().forEach((record) => {
            addRoute(record.path, record.name, "vue");
          });
        }
      } catch (_) {
        // Framework internals are best-effort; never break the page.
      }
    });
  };

  window.__jsowlCollector = {
    snapshot() {
      collectDOM(document);
      collectAnchors(document);
      collectVueRoutes();
      recordLocation("history-hook");
      try {
        performance.getEntriesByType("resource").forEach((entry) => add(entry.name));
      } catch (_) {}
      return {
        urls: Array.from(resourceURLs).sort(),
        routes: Array.from(routes.values()).sort((a, b) => a.path < b.path ? -1 : 1),
      };
    },
  };

  if (document.documentElement) startObservers();
  else document.addEventListener("DOMContentLoaded", startObservers, { once: true });
})();
