requirejs.config({
  baseUrl: "/assets",
  paths: {
    jquery: "lib/jquery.min",
    users: "pages/users",
    vue: "https://cdn.example.test/vue.min"
  }
});
define(["jquery", "users", "vue"], function ($, users, Vue) {});

