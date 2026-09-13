// Fixture: popular npm request libraries for AST extraction tests.
// Each call pairs an API URL (absolute or relative) with query/body params.
const API = "https://api.example.test";

// ---- axios (baseline, already covered) ----
axios.post("/login", { username, password });
axios.get("/user/list?page=2&size=20");

// ---- ky ----
ky.get("/v1/items?sort=desc", { searchParams: { tag: "new" } });
ky.post(API + "/v1/orders", { json: { sku: "A1", count: 3 } });
ky("https://gw.example.test/v1/ping", { method: "POST", json: { echo: 1 } });

// ---- ofetch / $fetch (unjs ecosystem) ----
$fetch("/api/session", { method: "POST", body: { token: sessionId } });
ofetch("https://api.example.test/v2/profile?uid=8", { method: "GET" });

// ---- jQuery ----
$.get("/legacy/list?catid=7");
$.post("/legacy/save", { title: "demo", status: 1 });
$.ajax({ url: "/legacy/detail?id=9", type: "PUT", data: { remark: "ok" } });

// ---- mini-program runtimes ----
wx.request({
  url: "https://api.weixin.example.test/pay/create",
  method: "POST",
  data: { openid: openid, amount: 100 },
});
uni.request({
  url: "/uni/user/info",
  data: { uid: 5 },
});

// ---- second tier: umi-request, alova, wretch, swr ----
request("/umix/list?state=open", { method: "GET" });
request(API + "/umix/submit", { method: "POST", data: { formId: 77 } });
alova.Get("/alova/config?section=mail");
alova.Post("https://api.example.test/alova/upload", { fileKey: "a.zip" });
wretch("/wretch/cart?uid=3").post({ sku: "B2" });
wretch(API + "/wretch/checkout").put({ address: "sh" });
useSWR("/swr/session?fields=all");

// ---- framework routes (vue already via url.vue-route elsewhere) ----
const reactRoutes = createBrowserRouter([
  { path: "/react/dashboard", element: h(Dashboard) },
  { path: "/react/settings", element: h(Settings) },
]);
oldStyleRouter(
  { path: "/v5/orders", component: Orders },
);

// ---- fetch & XHR (built-ins, regression) ----
fetch(API + "/v1/notes", {
  method: "POST",
  body: JSON.stringify({ title: noteTitle, content: noteBody }),
});
xhr.open("DELETE", "/v1/cache?key=static");
