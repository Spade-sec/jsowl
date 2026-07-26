var runtime = {};
runtime.p = "/static/";
var chunks = {"1": "users.hash"};
function loadChunk(id) {
  return runtime.p + chunks[id] + ".js";
}
