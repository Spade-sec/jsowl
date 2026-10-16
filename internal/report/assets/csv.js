// CSV building for the report exports. Kept in its own module so the
// escaping rules can be tested directly and so the dashboard has a single
// place that decides what a cell looks like.
//
// Two rules matter here:
//   1. RFC 4180 quoting — fields containing a comma, quote or newline are
//      wrapped in quotes and inner quotes are doubled.
//   2. Formula-injection defence — a field starting with = + - @ or a control
//      character is prefixed with a single quote, because spreadsheet apps
//      would otherwise evaluate a scan-controlled value as a formula. The
//      guard applies to the exported text only; report data is never altered.
(function (global) {
  'use strict';

  var FORMULA_PREFIX = /^[=+\-@\t\r]/;

  function toString(value) {
    return value === null || value === undefined ? '' : String(value);
  }

  function cell(value) {
    var out = toString(value);
    if (FORMULA_PREFIX.test(out)) out = "'" + out;
    if (/[",\n\r]/.test(out)) out = '"' + out.replace(/"/g, '""') + '"';
    return out;
  }

  // build renders header + rows as CRLF-delimited CSV. A BOM is prepended by
  // the downloader, not here, so the pure text stays easy to assert on.
  function build(header, rows) {
    var lines = [header.map(cell).join(',')];
    (rows || []).forEach(function (row) { lines.push(row.map(cell).join(',')); });
    return lines.join('\r\n');
  }

  // fileName keeps the export name to safe characters and pins the scope and
  // row count into it, so an export is never mislabelled.
  function fileName(scope, host, count) {
    var safeHost = toString(host).replace(/[^A-Za-z0-9._-]+/g, '_')
      .replace(/^_+|_+$/g, '').slice(0, 60) || 'report';
    var safeScope = toString(scope).replace(/[^A-Za-z0-9._-]+/g, '_') || 'export';
    return 'jsowl-' + safeScope + '-' + safeHost + '-' + toString(count) + '.csv';
  }

  global.JsOwlCSV = { cell: cell, build: build, fileName: fileName };
})(window);
