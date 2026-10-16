// Interactive report controller: overview dashboard, filtering workbench,
// detail drawer, CSV export and the printable delivery view.
//
// Conventions this file follows:
//   - Aggregates come from window.__DATA__.summary (computed once in Go), so
//     charts, tables, CSV and print all read the same numbers.
//   - Raw evidence is never recomputed: the raw-hit view is derived from
//     summary.groups[].sources[], which is the same evidence the drawer shows.
//   - Every DOM node is built with createElement/textContent. Target- or
//     scan-controlled text (hosts, rule names, values, source, AI output) is
//     never concatenated into innerHTML.
//   - Links only accept http(s) URLs and known report file names, so a
//     javascript: URL from a scan can never become a clickable link.
(function () {
  'use strict';

  var data = window.__DATA__ || {};
  var summary = data.summary || {};
  var groups = Array.isArray(summary.groups) ? summary.groups : [];
  var resources = Array.isArray(data.resources) ? data.resources : [];
  var endpoints = Array.isArray(data.endpoints) ? data.endpoints : [];
  var issues = Array.isArray(data.issues) ? data.issues : [];
  var params = Array.isArray(summary.params) ? summary.params : [];
  var charts = window.JsOwlCharts || {};

  var SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  // Host vocabulary: the values are the ones the Go side emits, so the report
  // renders what the scan classified instead of re-deriving it here.
  var HOST_KIND_LABELS = {
    domain: '域名', ipv4: 'IPv4', ipv6: 'IPv6', internal_host: '内部主机候选'
  };
  var HOST_KIND_ORDER = ['domain', 'ipv4', 'ipv6', 'internal_host'];
  var HOST_METHOD_LABELS = {
    url: 'URL 解析', ast_literal: 'AST 字面量',
    static_expression: '静态表达式', regex: '正则兜底'
  };
  var HOST_STATUS_LABELS = {
    recognized: '已识别后缀', custom: '自定义/保留后缀', unknown: '无后缀规则',
    unresolved: '层级未解析', not_applicable: '不适用'
  };
  var HOST_ATTR_LABELS = {
    private: '私网', loopback: '回环', link_local: '链路本地', multicast: '组播',
    unspecified: '未指定', unclassified: '未分类（未判定可达性）'
  };
  var HOST_NOTE_LABELS = {
    target: '扫描目标', resource: '资源', endpoint: '端点', endpoint_source: '端点来源',
    finding_source: '发现来源', email_domain: '邮箱域名', comment: '注释',
    dynamic_host: '动态表达式', reserved: '保留/特殊用途', public_suffix_only: '公共后缀本身'
  };
  var HOST_ORIGIN_LABELS = { js: '内容发现', scan: '扫描关联' };
  var UNKNOWN_HOST = '（未解析主机）';
  var UNRESOLVED_METHOD = '未知';
  var PRINT_SOFT_CAP = 200;
  var DEFAULT_PAGE_SIZE = 50;

  // ---------------------------------------------------------------- helpers

  function pick(object, camel, pascal) {
    if (!object) return undefined;
    if (object[camel] !== undefined && object[camel] !== null) return object[camel];
    if (object[pascal] !== undefined && object[pascal] !== null) return object[pascal];
    return undefined;
  }

  function text(value) {
    return value === undefined || value === null ? '' : String(value);
  }

  function setAttrs(node, attrs) {
    if (!attrs) return node;
    Object.keys(attrs).forEach(function (key) {
      var value = attrs[key];
      if (value === null || value === undefined) return;
      if (key === 'text') { node.textContent = String(value); return; }
      node.setAttribute(key, String(value));
    });
    return node;
  }

  function h(tag, attrs, children) {
    var node = document.createElement(tag);
    setAttrs(node, attrs);
    append(node, children);
    return node;
  }

  function append(node, children) {
    if (children === null || children === undefined || children === false) return node;
    (Array.isArray(children) ? children : [children]).forEach(function (child) {
      if (child === null || child === undefined || child === false) return;
      if (typeof child === 'string' || typeof child === 'number') {
        node.appendChild(document.createTextNode(String(child)));
      } else {
        node.appendChild(child);
      }
    });
    return node;
  }

  function clear(node) {
    if (node) node.textContent = '';
    return node;
  }

  function byId(id) { return document.getElementById(id); }

  // safeHref returns a link target only for http(s) URLs and for the report
  // files written next to this page; anything else (javascript:, data:, a
  // protocol-relative host) yields '' so the caller renders plain text.
  function safeHref(raw) {
    var value = text(raw).trim();
    if (!value) return '';
    if (/^https?:\/\//i.test(value)) return value;
    if (/^[\w一-龥.\-]+\.(html|txt)$/i.test(value)) return value;
    return '';
  }

  function severityRank(severity) {
    return SEVERITY_RANK[severity] || 0;
  }

  function severityLabel(severity) {
    var labels = { critical: '严重', high: '高', medium: '中', low: '低', info: '信息' };
    return labels[severity] || '未知';
  }

  function severityBadge(severity) {
    var level = SEVERITY_RANK[severity] ? severity : 'info';
    return h('span', { class: 'sev ' + level, text: severityLabel(severity) });
  }

  function chip(label, onClear) {
    var button = h('button', {
      type: 'button', class: 'chip-clear',
      title: '清除该筛选', 'aria-label': '清除筛选 ' + label
    }, '×');
    button.addEventListener('click', onClear);
    return h('span', { class: 'chip' }, [h('span', { class: 'chip-label', text: label }), button]);
  }

  function plural(count, unit) { return count + ' ' + unit; }

  function copyText(value, button) {
    var done = function () {
      if (!button) return;
      var original = button.getAttribute('data-label') || button.textContent;
      button.setAttribute('data-label', original);
      button.textContent = '已复制';
      setTimeout(function () { button.textContent = original; }, 1200);
    };
    var fallback = function () {
      var area = document.createElement('textarea');
      area.value = value;
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.appendChild(area);
      area.select();
      try { document.execCommand('copy'); done(); } catch (error) { /* clipboard unavailable */ }
      document.body.removeChild(area);
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(value).then(done, fallback);
    } else {
      fallback();
    }
  }

  function copyButton(label, valueOf) {
    var button = h('button', { type: 'button', class: 'copy-btn', text: label });
    button.addEventListener('click', function (event) {
      event.stopPropagation();
      copyText(typeof valueOf === 'function' ? valueOf() : valueOf, button);
    });
    return button;
  }

  function toast(message) {
    var node = byId('toast');
    if (!node) return;
    node.textContent = message;
    node.classList.add('visible');
    clearTimeout(toast.timer);
    toast.timer = setTimeout(function () { node.classList.remove('visible'); }, 3200);
  }

  function download(name, content, mime) {
    var blob = new Blob(['﻿' + content], { type: mime || 'text/csv;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var anchor = h('a', { href: url, download: name });
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    setTimeout(function () { URL.revokeObjectURL(url); }, 0);
  }

  // ------------------------------------------------------------- CSV export

  var csv = window.JsOwlCSV;

  function download(name, content, mime) {
    // The BOM is what makes Excel read the Chinese headers as UTF-8. It is
    // added to the exported blob only, and nothing leaves the browser.
    var blob = new Blob(['﻿' + content], { type: mime || 'text/csv;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var anchor = h('a', { href: url, download: name });
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    setTimeout(function () { URL.revokeObjectURL(url); }, 0);
  }

  // ----------------------------------------------------------- derived data

  // rawHits flattens the aggregated findings back into per-hit rows. The
  // flatten order is the aggregation order (severity first), so the R-numbers
  // are stable for a given scan result.
  var rawHits = (function () {
    var rows = [];
    groups.forEach(function (group) {
      (group.sources || []).forEach(function (source) {
        rows.push({
          groupId: group.id,
          ruleId: group.ruleId,
          ruleName: group.ruleName,
          category: group.category,
          severity: group.severity,
          value: group.value,
          url: text(source.url),
          domain: text(source.domain),
          line: source.line || 0,
          column: source.column || 0,
          context: source.context || [],
          ai: source.ai || null,
          verify: group.verify,
          confirmation: group.confirmation || '待人工验证'
        });
      });
    });
    rows.forEach(function (row, index) {
      row.id = 'R' + String(index + 1).padStart(4, '0');
    });
    return rows;
  })();

  function endpointHost(endpoint) {
    var raw = endpoint.url || endpoint.raw || '';
    var match = /^https?:\/\/([^/?#]+)/i.exec(raw);
    return match ? match[1] : UNKNOWN_HOST;
  }

  function endpointPath(endpoint) {
    var raw = endpoint.raw || '';
    if (raw && !/^https?:\/\//i.test(raw)) return raw;
    var value = endpoint.url || '';
    var match = /^https?:\/\/[^/?#]*([^?#]*)(\?[^#]*)?/.exec(value);
    return match ? (match[1] || '/') + (match[2] || '') : value;
  }

  function endpointMethod(endpoint) {
    var method = text(endpoint.method).trim().toUpperCase();
    return method ? method : UNRESOLVED_METHOD;
  }

  // Parameter names recorded for an endpoint, from the normalized spec, the
  // legacy body list and the probe response — labelled by origin, and 未提取
  // when the scan recovered nothing.
  function endpointParams(endpoint) {
    var rows = [];
    var spec = endpoint.spec || null;
    if (spec) {
      (spec.query || []).forEach(function (param) { rows.push({ origin: 'query', key: param.key, value: param.value, evidence: param.evidence }); });
      (spec.body || []).forEach(function (param) { rows.push({ origin: 'body', key: param.key, value: param.value, evidence: param.evidence }); });
    }
    (endpoint.body_params || endpoint.BodyParams || []).forEach(function (name) {
      if (!rows.some(function (row) { return row.origin === 'body' && row.key === name; })) {
        rows.push({ origin: 'body', key: name, value: '', evidence: '' });
      }
    });
    (endpoint.response_params || endpoint.ResponseParams || []).forEach(function (name) {
      rows.push({ origin: 'response', key: name, value: '', evidence: '' });
    });
    return rows;
  }

  var domains = (summary.domains || []).slice();
  var severityRows = (summary.severityMetrics || []).filter(function (row) {
    return row.groups > 0 || row.hits > 0;
  });
  var findingDomains = (function () {
    var seen = {};
    groups.forEach(function (group) {
      (group.domains || []).forEach(function (domain) { seen[domain] = true; });
    });
    return Object.keys(seen).sort();
  })();
  var endpointDomains = (function () {
    var seen = {};
    apiEndpoints().forEach(function (endpoint) { seen[endpointHost(endpoint)] = true; });
    return Object.keys(seen).sort();
  })();
  var endpointMethods = (function () {
    var seen = {};
    apiEndpoints().forEach(function (endpoint) { seen[endpointMethod(endpoint)] = true; });
    return Object.keys(seen).sort();
  })();
  // hostRows merges the two host populations into one readable list. The same
  // host found in content and touched by the scan appears once, with both
  // origins recorded in its 数据来源 cell; the counts themselves stay separate
  // in the summary, which is where the two populations are never added up.
  var hostRows = (function () {
    var index = {};
    var rows = [];
    function add(asset, origin) {
      var value = text(asset.value);
      if (!value) return;
      var key = text(asset.kind) + '|' + value;
      var row = index[key];
      if (!row) {
        row = {
          key: key, kind: text(asset.kind), value: value,
          registrable: text(asset.registrable_domain),
          suffix: text(asset.public_suffix),
          subdomain: text(asset.subdomain),
          status: text(asset.suffix_status),
          zone: text(asset.zone),
          attributes: asset.attributes || [],
          occurrences: 0, origins: [], sources: [], vendor: false
        };
        index[key] = row;
        rows.push(row);
      }
      if (row.origins.indexOf(origin) === -1) row.origins.push(origin);
      if (row.registrable === '' && text(asset.registrable_domain)) {
        row.registrable = text(asset.registrable_domain);
      }
      row.occurrences += asset.occurrences || (asset.sources || []).length;
      row.vendor = row.vendor || !!asset.vendor;
      (asset.sources || []).forEach(function (source) {
        row.sources.push({
          origin: origin,
          url: text(source.url || source.source_url || source.SourceURL),
          raw: text(source.raw),
          line: source.line || 0,
          column: source.column || 0,
          method: text(source.extraction_method || source.method),
          note: text(source.note),
          associated: text(source.associated_url),
          context: source.context_lines || source.context || source.ContextLines || []
        });
      });
    }
    var content = Array.isArray(data.hosts) ? data.hosts : [];
    var scan = Array.isArray(data.scanHosts) ? data.scanHosts : [];
    content.forEach(function (asset) { add(asset, 'js'); });
    scan.forEach(function (asset) { add(asset, 'scan'); });
    // Deterministic order: kind, then value, so the list never depends on how
    // the two populations happened to be merged.
    rows.sort(function (left, right) {
      var leftRank = HOST_KIND_ORDER.indexOf(left.kind);
      var rightRank = HOST_KIND_ORDER.indexOf(right.kind);
      if (leftRank !== rightRank) return (leftRank < 0 ? 99 : leftRank) - (rightRank < 0 ? 99 : rightRank);
      return compareReportValues(left.value, right.value);
    });
    rows.forEach(function (row) {
      row.originLabel = row.origins.map(function (origin) {
        return HOST_ORIGIN_LABELS[origin] || origin;
      }).join(' / ');
      row.groupKey = row.registrable || row.value;
    });
    return rows;
  })();

  function hostKindLabel(kind) { return HOST_KIND_LABELS[kind] || kind || '未知'; }

  function hostStatusLabel(status) { return HOST_STATUS_LABELS[status] || status || '—'; }

  function hostNoteLabel(note) {
    if (!note) return '';
    return note.split(',').map(function (part) {
      var trimmed = part.trim();
      return HOST_NOTE_LABELS[trimmed] || trimmed;
    }).join('、');
  }

  function hostAttributeLabel(attribute) { return HOST_ATTR_LABELS[attribute] || attribute; }

  var hostKinds = (function () {
    var seen = {};
    hostRows.forEach(function (row) { seen[row.kind] = true; });
    return HOST_KIND_ORDER.filter(function (kind) { return seen[kind]; });
  })();

  var categoryLabels = (function () {
    var labels = {};
    groups.forEach(function (group) { labels[group.category] = group.categoryLabel; });
    return labels;
  })();

  // ----------------------------------------------------------------- state

  var state = {
    tab: 'overview',
    findingsView: 'group',
    severity: '',
    category: '',
    rule: '',
    domain: '',
    source: '',
    search: '',
    page: 1,
    pageSize: DEFAULT_PAGE_SIZE,
    sort: null,
    endpointDomain: '',
    endpointMethod: '',
    endpointSearch: '',
    endpointPage: 1,
    hostKind: '',
    hostSearch: '',
    hostGroup: 'host',
    hostPage: 1,
    hostSort: null,
    endpointSort: null,
    resourcePage: 1,
    resourceSort: null,
    issueSort: null,
    paramSearch: '',
    openNodes: {},
    closedNodes: {},
    printScope: 'full'
  };

  // --------------------------------------------------------------- sorting

  var sortState = {};
  var sortColumns = {};
  var boundTables = {};

  function sortRows(name, rows, valueOf) {
    var active = sortState[name];
    var column = active && sortColumns[name] ? sortColumns[name][active.column] : null;
    if (!column) return rows;
    var direction = active.direction;
    return rows.slice().sort(function (left, right) {
      var a = valueOf(left, column.key);
      var b = valueOf(right, column.key);
      if (column.numeric) {
        return direction * ((Number(a) || 0) - (Number(b) || 0));
      }
      return direction * (compareReportValues(a, b) || compareReportValues(left[column.key], right[column.key]));
    });
  }

  // ensureSortable builds a table's header row once per column layout and
  // hands header interaction to the shared bindReportSort controller, so
  // click / Enter / Space and aria-sort behave exactly like the split
  // reports. It is deliberately not called on every render: rebinding would
  // reset the controller's direction state and lose the sort indicator.
  function ensureSortable(name, table, columns, onChange) {
    if (!table || boundTables[name] === columns) return;
    var row = table.tHead.rows[0];
    clear(row);
    columns.forEach(function (column) {
      var cell = h('th', { scope: 'col', text: column.label });
      if (column.width) cell.style.width = column.width;
      row.appendChild(cell);
    });
    sortColumns[name] = columns;
    boundTables[name] = columns;
    bindReportSort(table, function (index, direction) {
      sortState[name] = { column: index, direction: direction };
      onChange();
    });
  }

  // --------------------------------------------------------------- filters

  function matchesSeverity(item) {
    return !state.severity || item.severity === state.severity;
  }

  function filterGroups() {
    var query = state.search.trim().toLowerCase();
    return groups.filter(function (group) {
      if (!matchesSeverity(group)) return false;
      if (state.category && group.category !== state.category) return false;
      if (state.rule && group.ruleName !== state.rule) return false;
      if (state.domain && (group.domains || []).indexOf(state.domain) === -1) return false;
      if (state.source && !(group.sources || []).some(function (source) {
        return matchesSource(source.url);
      })) return false;
      if (!query) return true;
      var haystack = [
        group.id, group.ruleName, group.ruleId, group.value, group.categoryLabel,
        (group.domains || []).join(' '),
        text(group.ai && group.ai.reason)
      ].join(' ').toLowerCase();
      return haystack.indexOf(query) !== -1;
    });
  }

  // matchesSource applies the target-tree node filter: the node path is a URL
  // prefix, so a host node matches every file under it.
  function matchesSource(url) {
    if (!state.source) return true;
    var value = text(url);
    return value === state.source ||
      value.indexOf(state.source + '/') === 0 ||
      value.indexOf(state.source + '?') === 0;
  }

  function filterRawHits() {
    var query = state.search.trim().toLowerCase();
    return rawHits.filter(function (row) {
      if (!matchesSeverity(row)) return false;
      if (state.category && row.category !== state.category) return false;
      if (state.rule && row.ruleName !== state.rule) return false;
      if (state.domain && row.domain !== state.domain) return false;
      if (!matchesSource(row.url)) return false;
      if (!query) return true;
      return [row.id, row.ruleName, row.ruleId, row.value, row.url, row.domain]
        .join(' ').toLowerCase().indexOf(query) !== -1;
    });
  }

  // Endpoints and routes are separate views: the API tab lists backend
  // endpoints (everything not typed as a route), and the route tab owns the
  // framework routes, so a route never shows up here as an unknown method.
  function apiEndpoints() {
    return endpoints.filter(function (endpoint) { return text(endpoint.type) !== 'route'; });
  }

  function filterEndpoints() {
    var query = state.endpointSearch.trim().toLowerCase();
    return apiEndpoints().filter(function (endpoint) {
      if (state.endpointDomain && endpointHost(endpoint) !== state.endpointDomain) return false;
      if (state.endpointMethod && endpointMethod(endpoint) !== state.endpointMethod) return false;
      if (!query) return true;
      var params = endpointParams(endpoint).map(function (row) { return row.key; }).join(' ');
      return [endpointMethod(endpoint), endpointPath(endpoint), endpoint.url, endpoint.source_url, params]
        .join(' ').toLowerCase().indexOf(query) !== -1;
    });
  }

  function filterRoutes() {
    var query = state.endpointSearch.trim().toLowerCase();
    return endpoints.filter(function (endpoint) {
      if (text(endpoint.type) !== 'route') return false;
      if (!query) return true;
      return [endpoint.url, endpoint.raw, endpoint.source_url, endpoint.source]
        .join(' ').toLowerCase().indexOf(query) !== -1;
    });
  }

  // --------------------------------------------------------- filter chips

  function renderChips(container, entries, onClearAll) {
    clear(container);
    var active = entries.filter(function (entry) { return entry.value; });
    if (active.length === 0) return;
    active.forEach(function (entry) {
      container.appendChild(chip(entry.label + '：' + entry.display, entry.clear));
    });
    if (active.length > 1) {
      var button = h('button', { type: 'button', class: 'chip-reset', text: '清除全部筛选' });
      button.addEventListener('click', onClearAll);
      container.appendChild(button);
    }
  }

  // --------------------------------------------------------- target tree

  function buildTree() {
    var root = { name: '站点', children: {}, hits: 0 };
    var hitCount = {};
    groups.forEach(function (group) {
      (group.sources || []).forEach(function (source) {
        if (!source.url) return;
        hitCount[source.url] = (hitCount[source.url] || 0) + 1;
      });
    });
    Object.keys(hitCount).sort().forEach(function (url) {
      var parsed = /^https?:\/\/([^/?#]+)(\/[^?#]*)?/i.exec(url);
      var origin = parsed ? 'https://' + parsed[1] : url;
      var host = parsed ? parsed[1] : url;
      var path = parsed && parsed[2] ? parsed[2] : '';
      if (!root.children[origin]) {
        root.children[origin] = {
          name: host, path: origin, children: {}, hits: 0, host: true,
          expanded: !state.closedNodes[origin]
        };
      }
      var node = root.children[origin];
      node.hits += hitCount[url];
      var current = node;
      var prefix = '';
      path.split('/').filter(Boolean).forEach(function (part, index) {
        prefix += '/' + part;
        var key = origin + prefix;
        if (!current.children[key]) {
          current.children[key] = {
            name: part, path: parsed ? parsed[1] + prefix : key, children: {}, hits: 0,
            expanded: index < 1 && !state.closedNodes[key]
          };
        }
        current.children[key].hits += hitCount[url];
        current = current.children[key];
      });
    });
    return root;
  }

  function renderTree() {
    var container = byId('tree-panel');
    if (!container) return;
    clear(container);
    if (groups.length === 0) {
      container.appendChild(h('p', { class: 'muted', text: '暂无可展示的来源节点' }));
      return;
    }
    renderTreeNode(buildTree(), container);
  }

  function renderTreeNode(node, container) {
    Object.keys(node.children).sort().forEach(function (key) {
      var child = node.children[key];
      var hasChildren = Object.keys(child.children).length > 0;
      var caret = h('span', {
        class: 'tree-caret' + (hasChildren ? '' : ' leaf') + (child.expanded ? '' : ' collapsed'),
        text: '▼', 'aria-hidden': 'true'
      });
      var row = h('div', {
        class: 'tree-row' + (state.source === child.path ? ' active' : ''),
        role: 'button', tabindex: '0',
        'aria-label': child.name + '，' + child.hits + ' 次命中，点击筛选'
      }, [
        caret,
        h('span', { class: 'tree-icon', text: child.host ? '◎' : hasChildren ? '▣' : '□' }),
        h('span', { class: 'tree-label', text: child.name, title: child.name }),
        child.hits > 0 ? h('span', { class: 'tree-count', text: String(child.hits) }) : null
      ]);
      var activate = function () {
        var path = child.path || '';
        state.source = state.source === path ? '' : path;
        state.page = 1;
        activateTab('findings');
        renderTree();
        renderFindings();
      };
      row.addEventListener('click', activate);
      row.addEventListener('keydown', function (event) {
        if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); activate(); }
      });
      if (hasChildren) {
        caret.addEventListener('click', function (event) {
          event.stopPropagation();
          child.expanded = !child.expanded;
          var nodeKey = key;
          if (child.expanded) { delete state.closedNodes[nodeKey]; } else { state.closedNodes[nodeKey] = true; }
          renderTree();
        });
      }
      container.appendChild(row);
      if (hasChildren) {
        var children = h('div', { class: 'tree-children' + (child.expanded ? ' open' : '') });
        renderTreeNode(child, children);
        container.appendChild(children);
      }
    });
  }

  // -------------------------------------------------------------- overview

  function renderMetricCards(container, metrics) {
    clear(container);
    (metrics || []).forEach(function (metric) {
      var card = h('article', { class: 'card metric-card', id: 'metric-' + metric.key }, [
        h('div', { class: 'card-label', text: metric.label }),
        h('div', { class: 'card-value', text: String(metric.value) }),
        metric.sub ? h('div', {
          class: 'card-sub',
          text: (metric.subLabel || '小计') + ' ' + metric.sub
        }) : null,
        h('details', { class: 'card-note' }, [
          h('summary', { text: '统计口径' }),
          h('p', { class: 'muted', text: metric.note })
        ])
      ]);
      container.appendChild(card);
    });
  }

  function renderSeverityCards(container) {
    clear(container);
    if (severityRows.length === 0) {
      // No hits at all: one honest zero card beats a row of zeroes that could
      // be mistaken for findings that exist.
      container.appendChild(h('article', { class: 'card metric-card', id: 'metric-nohit' }, [
        h('div', { class: 'card-label', text: '风险等级' }),
        h('div', { class: 'card-value', text: '0' }),
        h('div', { class: 'card-sub', text: '本次扫描未命中任何规则' }),
        h('details', { class: 'card-note' }, [
          h('summary', { text: '统计口径' }),
          h('p', {
            class: 'muted',
            text: '等级为规则命中等级。本次没有任何命中，因此没有待核查发现；这不等于目标不存在风险。'
          })
        ])
      ]));
      return;
    }
    severityRows.forEach(function (row) {
      container.appendChild(h('article', {
        class: 'card metric-card severity-card sev-' + (SEVERITY_RANK[row.severity] ? row.severity : 'info'),
        id: 'metric-' + row.severity
      }, [
        h('div', { class: 'card-label' }, [severityBadge(row.severity)]),
        h('div', { class: 'card-value', text: String(row.groups) }),
        h('div', { class: 'card-sub', text: '聚合发现 · 原始命中 ' + row.hits }),
        h('details', { class: 'card-note' }, [
          h('summary', { text: '统计口径' }),
          h('p', {
            class: 'muted',
            text: '聚合发现：按 规则 + 分类 + 等级 + 完整值 合并后的条数；原始命中：规则每一次匹配。' +
              '涉及域名 ' + row.domains + ' 个。等级为规则命中等级，非人工确认结论。'
          })
        ])
      ]));
    });
  }

  function renderSeverityTable() {
    var tbody = byId('severity-table-body');
    if (!tbody) return;
    clear(tbody);
    if (severityRows.length === 0) {
      tbody.appendChild(h('tr', null, h('td', { colspan: '4', class: 'empty', text: '本次扫描未命中任何规则' })));
      return;
    }
    severityRows.forEach(function (row) {
      tbody.appendChild(h('tr', { dataset: {} }, [
        h('td', null, severityBadge(row.severity)),
        h('td', { text: String(row.groups) }),
        h('td', { text: String(row.hits) }),
        h('td', { text: String(row.domains) })
      ]));
    });
  }

  function renderCharts() {
    if (!charts.donut) return;
    charts.donut(byId('severity-chart'), severityRows.map(function (row) {
      return { key: row.severity, label: severityLabel(row.severity) + '（' + row.severity + '）', count: row.groups, severity: row.severity };
    }), {
      unit: ' 条聚合发现',
      centerLabel: '聚合发现',
      title: '严重性分布',
      actionLabel: '点击筛选该等级',
      emptyText: '本次扫描未命中任何规则',
      onSelect: function (key) {
        state.severity = state.severity === key ? '' : key;
        state.page = 1;
        activateTab('findings');
        renderFindings();
      }
    });

    charts.barList(byId('type-chart'), (summary.types || []).map(function (bucket) {
      return { key: bucket.key, label: bucket.label, count: bucket.count, severity: bucket.severity };
    }), {
      unit: ' 次命中',
      actionLabel: '点击筛选该规则',
      emptyText: '本次扫描未命中任何规则',
      onSelect: function (key) {
        state.rule = state.rule === key ? '' : key;
        state.page = 1;
        activateTab('findings');
        renderFindings();
      }
    });

    charts.barList(byId('domain-chart'), domains.map(function (bucket) {
      return {
        key: bucket.host,
        label: bucket.label || bucket.host,
        count: bucket.endpoints,
        severity: bucket.endpoints > 0 ? 'low' : 'info'
      };
    }), {
      unit: ' 个 API 端点',
      actionLabel: '点击筛选该域名的端点',
      emptyText: '本次未采集到端点',
      labelLimit: 32,
      onSelect: function (key) {
        state.endpointDomain = state.endpointDomain === key ? '' : key;
        state.endpointPage = 1;
        activateTab('endpoints');
        renderEndpoints();
      }
    });

    charts.barList(byId('method-chart'), (summary.methods || []).map(function (bucket) {
      return { key: bucket.key, label: bucket.label, count: bucket.count, severity: bucket.key === UNRESOLVED_METHOD ? 'info' : 'low' };
    }), {
      unit: ' 个端点',
      actionLabel: '点击筛选该方法',
      emptyText: '本次未采集到端点',
      onSelect: function (key) {
        state.endpointMethod = state.endpointMethod === key ? '' : key;
        state.endpointPage = 1;
        activateTab('endpoints');
        renderEndpoints();
      }
    });
  }

  function renderKeyFindings() {
    var container = byId('key-findings');
    if (!container) return;
    clear(container);
    var keys = summary.key || [];
    if (keys.length === 0) {
      container.appendChild(h('p', {
        class: 'empty',
        text: '本次扫描没有命中任何规则，未产生待核查发现。这不是"未发现风险"的结论，只说明当前规则集未命中。'
      }));
      return;
    }
    var table = h('table', { class: 'key-table' });
    var head = h('thead', null, h('tr', null, [
      h('th', { text: '等级', scope: 'col' }),
      h('th', { text: '类型', scope: 'col' }),
      h('th', { text: '摘要', scope: 'col' }),
      h('th', { text: '来源', scope: 'col' }),
      h('th', { text: '核查建议', scope: 'col' }),
      h('th', { text: '证据', scope: 'col' })
    ]));
    var body = h('tbody');
    keys.forEach(function (group) {
      var link = h('button', {
        type: 'button', class: 'link-button', text: '查看证据',
        'aria-label': '查看 ' + group.ruleName + ' 的证据'
      });
      link.addEventListener('click', function () { openGroup(group); });
      body.appendChild(h('tr', null, [
        h('td', null, severityBadge(group.severity)),
        h('td', null, [
          h('div', { class: 'rule-name', text: group.ruleName }),
          h('div', { class: 'muted', text: group.ruleId })
        ]),
        h('td', { class: 'value-cell' }, h('code', { text: group.summary || group.value })),
        h('td', null, [
          h('div', { text: group.sources.length + ' 处来源' }),
          h('div', { class: 'muted', text: (group.domains || []).join(', ') || UNKNOWN_HOST })
        ]),
        h('td', { class: 'muted', text: group.verify }),
        h('td', null, link)
      ]));
    });
    table.appendChild(head);
    table.appendChild(body);
    container.appendChild(table);
    container.appendChild(h('p', {
      class: 'muted',
      text: '排序规则：等级由高到低 → 命中次数由多到少 → 规则名 → 完整值；不使用综合评分。'
    }));
  }

  // renderHostMetrics shows the two host populations side by side. They are
  // never summed: the cards state which question each number answers.
  function renderHostMetrics() {
    var metrics = (summary.hosts || {}).metrics || [];
    var content = byId('host-content-metrics');
    var scan = byId('host-scan-metrics');
    if (!content || !scan) return;
    clear(content);
    clear(scan);
    if (metrics.length === 0) {
      content.appendChild(h('p', { class: 'chart-empty', text: '本次未发现主机' }));
      scan.appendChild(h('p', { class: 'chart-empty', text: '本次未发现主机' }));
      return;
    }
    metrics.forEach(function (entry) {
      content.appendChild(h('article', { class: 'card metric-card', id: 'host-content-' + entry.kind }, [
        h('div', { class: 'card-label', text: entry.label }),
        h('div', { class: 'card-value', text: String(entry.content) })
      ]));
      scan.appendChild(h('article', { class: 'card metric-card', id: 'host-scan-' + entry.kind }, [
        h('div', { class: 'card-label', text: entry.label }),
        h('div', { class: 'card-value', text: String(entry.scan) })
      ]));
    });
    var hosts = summary.hosts || {};
    content.appendChild(h('p', { class: 'muted', text: '共 ' + (hosts.contentTotal || 0) + ' 个主机' }));
    scan.appendChild(h('p', {
      class: 'muted',
      text: '共 ' + (hosts.scanTotal || 0) + ' 个主机 · 与内容发现重合 ' + (hosts.correlated || 0) + ' 个'
    }));
  }

  function renderHostNotes() {
    var container = byId('host-notes');
    if (!container) return;
    clear(container);
    (summary.hosts && summary.hosts.notes ? summary.hosts.notes : []).forEach(function (note) {
      container.appendChild(h('li', { text: note }));
    });
    var hosts = summary.hosts || {};
    if (hosts.pslVersion) {
      container.appendChild(h('li', {
        text: '公共后缀列表快照：' + hosts.pslVersion +
          (hosts.pslCommit ? '（' + hosts.pslCommit.slice(0, 12) + '）' : '') +
          '；状态 ' + (hosts.pslStatus === 'ok' ? '正常' : '未解析')
      }));
    }
  }

  function renderOverview() {
    renderMetricCards(byId('attack-metrics'), summary.attackMetrics || []);
    renderSeverityCards(byId('security-metrics'));
    renderHostMetrics();
    renderHostNotes();
    renderSeverityTable();
    renderCharts();
    renderKeyFindings();
    var notes = byId('overview-notes');
    clear(notes);
    [
      '规则命中等级：来自规则定义（critical / high / medium / low / info），本报告中的所有等级都是这一种。',
      'AI 辅助评估：仅在扫描启用 -ai 时存在，是模型给出的参考意见，不是结论；本报告共包含 ' +
        (summary.aiCount || 0) + ' 条带 AI 评估的命中。',
      '人工确认结果：本次报告没有人工确认数据，所有发现的核查状态均为「待人工验证」。',
      '这不是完整的渗透测试结论：报告只呈现自动采集与规则匹配的结果，未给出 CVSS 评分、风险等级结论或可利用性判定。' +
        (summary.attackNote ? ' ' + summary.attackNote : '')
    ].forEach(function (line) {
      notes.appendChild(h('li', { text: line }));
    });
  }

  // -------------------------------------------------------- findings view

  var groupColumns = [
    { key: 'id', label: '编号', width: '76px' },
    { key: 'severity', label: '等级', width: '84px' },
    { key: 'ruleName', label: '规则', width: '200px' },
    { key: 'categoryLabel', label: '分类', width: '90px' },
    { key: 'value', label: '完整值' },
    { key: 'sourceCount', label: '来源数', width: '76px', numeric: true },
    { key: 'hits', label: '命中次数', width: '84px', numeric: true },
    { key: 'confirmation', label: '核查状态', width: '110px' }
  ];
  var rawColumns = [
    { key: 'id', label: '编号', width: '76px' },
    { key: 'severity', label: '等级', width: '84px' },
    { key: 'ruleName', label: '规则', width: '200px' },
    { key: 'value', label: '完整值' },
    { key: 'url', label: '来源 URL', width: '280px' },
    { key: 'line', label: '行', width: '60px', numeric: true },
    { key: 'column', label: '列', width: '60px', numeric: true }
  ];
  var endpointColumns = [
    { key: 'method', label: '方法', width: '90px' },
    { key: 'path', label: '路径' },
    { key: 'domain', label: '域名', width: '180px' },
    { key: 'evidence', label: '证据', width: '100px' },
    { key: 'params', label: '参数', width: '80px', numeric: true },
    { key: 'source', label: '来源', width: '260px' },
    { key: 'authorized', label: '授权', width: '70px' },
    { key: 'status', label: '状态', width: '90px', numeric: true }
  ];
  var resourceColumns = [
    { key: 'type', label: '类型', width: '100px' },
    { key: 'url', label: 'URL' },
    { key: 'status', label: '状态', width: '80px', numeric: true },
    { key: 'size', label: '大小', width: '100px', numeric: true },
    { key: 'local', label: '本地路径', width: '240px' }
  ];

  function groupSortValue(row, key) {
    if (key === 'severity') return severityRank(row.severity);
    if (key === 'sourceCount') return (row.sources || []).length;
    return row[key];
  }

  function rawSortValue(row, key) {
    if (key === 'severity') return severityRank(row.severity);
    return row[key];
  }

  function renderFindingsFilters() {
    var container = byId('findings-chips');
    renderChips(container, [
      {
        value: state.severity, label: '等级', display: severityLabel(state.severity),
        clear: function () { state.severity = ''; byId('severity').value = ''; state.page = 1; renderFindings(); }
      },
      {
        value: state.category, label: '分类', display: categoryLabels[state.category] || state.category,
        clear: function () { state.category = ''; byId('category').value = ''; state.page = 1; renderFindings(); }
      },
      {
        value: state.rule, label: '规则', display: state.rule,
        clear: function () { state.rule = ''; byId('rule').value = ''; state.page = 1; renderFindings(); }
      },
      {
        value: state.domain, label: '域名', display: state.domain,
        clear: function () { state.domain = ''; byId('domain').value = ''; state.page = 1; renderFindings(); }
      },
      {
        value: state.source, label: '来源节点', display: state.source,
        clear: function () { state.source = ''; state.page = 1; renderTree(); renderFindings(); }
      },
      {
        value: state.search, label: '关键词', display: state.search,
        clear: function () { state.search = ''; byId('search').value = ''; state.page = 1; renderFindings(); }
      }
    ], function () {
      state.severity = ''; state.category = ''; state.rule = '';
      state.domain = ''; state.source = ''; state.search = '';
      state.page = 1;
      byId('severity').value = ''; byId('category').value = '';
      byId('rule').value = ''; byId('domain').value = ''; byId('search').value = '';
      renderTree();
      renderFindings();
    });
  }

  // syncControls mirrors filter state back into the toolbar controls, so a
  // chart drill-down (which sets state directly) is reflected in the selects
  // instead of leaving them showing 全部.
  function syncControls(pairs) {
    Object.keys(pairs).forEach(function (id) {
      var node = byId(id);
      if (node && node.value !== pairs[id]) node.value = pairs[id];
    });
  }

  function renderFindings() {
    var isGroup = state.findingsView === 'group';
    var columns = isGroup ? groupColumns : rawColumns;
    syncControls({
      severity: state.severity,
      category: state.category,
      rule: state.rule,
      domain: state.domain,
      search: state.search,
      'findings-view': state.findingsView
    });
    ensureSortable('findings', byId('findings-table'), columns, function () {
      state.page = 1;
      renderFindings();
    });

    // Aggregation order (and the raw flatten order) is already the documented
    // default: severity first, then hit count, rule name and value.
    var rows = isGroup
      ? sortRows('findings', filterGroups(), groupSortValue)
      : sortRows('findings', filterRawHits(), rawSortValue);

    var total = rows.length;
    var totalPages = Math.max(1, Math.ceil(total / state.pageSize));
    state.page = Math.min(Math.max(1, state.page), totalPages);
    var start = (state.page - 1) * state.pageSize;
    var pageRows = rows.slice(start, start + state.pageSize);

    var body = byId('findings-body');
    clear(body);
    if (pageRows.length === 0) {
      body.appendChild(h('tr', null, h('td', {
        colspan: String(columns.length), class: 'empty',
        text: groups.length === 0 ? '本次扫描未命中任何规则' : '没有符合当前筛选条件的记录'
      })));
    } else if (isGroup) {
      pageRows.forEach(function (group) {
        var row = h('tr', { tabindex: '0', class: 'clickable-row', 'aria-label': '打开 ' + group.id + ' 详情' });
        append(row, [
          h('td', null, h('code', { text: group.id })),
          h('td', null, severityBadge(group.severity)),
          h('td', null, [
            h('div', { class: 'rule-name', text: group.ruleName }),
            h('div', { class: 'rule-id', text: group.ruleId })
          ]),
          h('td', { text: group.categoryLabel }),
          h('td', { class: 'value-cell' }, h('code', { text: group.value })),
          h('td', { text: String((group.sources || []).length) }),
          h('td', { text: String(group.hits) }),
          h('td', { class: 'muted', text: group.confirmation })
        ]);
        openOnActivate(row, function () { openGroup(group); });
        body.appendChild(row);
      });
    } else {
      pageRows.forEach(function (hit) {
        var href = safeHref(hit.url);
        var row = h('tr', { tabindex: '0', class: 'clickable-row', 'aria-label': '打开 ' + hit.id + ' 详情' });
        append(row, [
          h('td', null, h('code', { text: hit.id })),
          h('td', null, severityBadge(hit.severity)),
          h('td', null, [
            h('div', { class: 'rule-name', text: hit.ruleName }),
            h('div', { class: 'rule-id', text: hit.ruleId })
          ]),
          h('td', { class: 'value-cell' }, h('code', { text: hit.value })),
          h('td', { class: 'source-cell' }, href
            ? h('a', { href: href, target: '_blank', rel: 'noopener noreferrer' }, h('code', { text: hit.url }))
            : h('code', { text: hit.url || '—' })),
          h('td', { text: String(hit.line) }),
          h('td', { text: String(hit.column) })
        ]);
        openOnActivate(row, function () { openGroup(findGroup(hit.groupId)); });
        body.appendChild(row);
      });
    }

    byId('findings-count').textContent = total === 0
      ? '0 条'
      : (start + 1) + '-' + (start + pageRows.length) + ' / ' + total + ' 条 · ' +
        (isGroup ? '聚合视图（按 规则+分类+等级+值 合并）' : '原始命中视图（每条匹配一行）');
    renderPagination(byId('findings-pagination'), state.page, totalPages, function (page) {
      state.page = page;
      renderFindings();
    });
    var exportButton = byId('findings-export');
    if (exportButton) {
      exportButton.textContent = '导出当前筛选结果（' + total + ' 条' + (isGroup ? '，聚合' : '，原始命中') + '）';
      exportButton.disabled = total === 0;
    }
    renderFindingsFilters();
  }

  function openOnActivate(node, activate) {
    node.addEventListener('click', activate);
    node.addEventListener('keydown', function (event) {
      if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); activate(); }
    });
  }

  function findGroup(id) {
    for (var index = 0; index < groups.length; index++) {
      if (groups[index].id === id) return groups[index];
    }
    return null;
  }

  function renderPagination(container, page, totalPages, onGo) {
    if (!container) return;
    clear(container);
    if (totalPages <= 1) return;
    container.appendChild(h('div', { class: 'pagination', role: 'navigation', 'aria-label': '分页' }, [
      pageButton('上一页', page <= 1, function () { onGo(page - 1); }),
      h('span', { class: 'page-info', text: '第 ' + page + ' / ' + totalPages + ' 页' }),
      pageButton('下一页', page >= totalPages, function () { onGo(page + 1); })
    ]));
  }

  function pageButton(label, disabled, onClick) {
    var button = h('button', { type: 'button', text: label, disabled: disabled ? 'disabled' : null });
    if (!disabled) button.addEventListener('click', onClick);
    return button;
  }

  // ------------------------------------------------------------ endpoints

  function renderEndpoints() {
    syncControls({
      'ep-domain': state.endpointDomain,
      'ep-method': state.endpointMethod,
      'ep-search': state.endpointSearch
    });
    ensureSortable('endpoints', byId('endpoints-table'), endpointColumns, function () {
      state.endpointPage = 1;
      renderEndpoints();
    });

    var rows = filterEndpoints().map(function (endpoint) {
      return {
        raw: endpoint,
        method: endpointMethod(endpoint),
        path: endpointPath(endpoint),
        domain: endpointHost(endpoint),
        evidence: text(endpoint.evidence) || 'static',
        params: endpointParams(endpoint).length,
        source: text(endpoint.source_url),
        authorized: text(endpoint.authorized),
        status: endpoint.status_code || 0
      };
    });
    rows = sortRows('endpoints', rows, function (row, key) { return row[key]; });

    var total = rows.length;
    var totalPages = Math.max(1, Math.ceil(total / DEFAULT_PAGE_SIZE));
    state.endpointPage = Math.min(Math.max(1, state.endpointPage), totalPages);
    var start = (state.endpointPage - 1) * DEFAULT_PAGE_SIZE;
    var pageRows = rows.slice(start, start + DEFAULT_PAGE_SIZE);

    var body = byId('endpoints-body');
    clear(body);
    if (pageRows.length === 0) {
      body.appendChild(h('tr', null, h('td', {
        colspan: '8', class: 'empty', text: endpoints.length === 0 ? '本次未采集到端点' : '没有符合当前筛选条件的端点'
      })));
    }
    pageRows.forEach(function (row) {
      var endpoint = row.raw;
      var tr = h('tr', { tabindex: '0', class: 'clickable-row', 'aria-label': '打开端点详情 ' + row.path });
      append(tr, [
        h('td', null, h('span', {
          class: 'method-tag ' + (row.method === UNRESOLVED_METHOD ? 'unknown' : row.method.toLowerCase()),
          text: row.method
        })),
        h('td', { class: 'path-cell' }, h('code', { text: row.path })),
        h('td', { class: 'muted', text: row.domain }),
        h('td', null, h('span', { class: 'sev ' + (row.evidence === 'runtime' ? 'runtime' : row.evidence === 'full-url' ? 'high' : 'info'), text: row.evidence })),
        h('td', { text: row.params === 0 ? '未提取' : String(row.params) }),
        h('td', { class: 'source-cell' }, h('code', { text: row.source || '—' })),
        h('td', { text: row.authorized === 'true' ? '是' : '否' }),
        h('td', { text: row.status ? String(row.status) : '未探测' })
      ]);
      openOnActivate(tr, function () { openEndpoint(endpoint); });
      body.appendChild(tr);
    });

    byId('endpoints-count').textContent = total === 0 ? '0 个端点'
      : (start + 1) + '-' + (start + pageRows.length) + ' / ' + total + ' 个端点';
    renderPagination(byId('endpoints-pagination'), state.endpointPage, totalPages, function (page) {
      state.endpointPage = page;
      renderEndpoints();
    });
    renderChips(byId('endpoints-chips'), [
      {
        value: state.endpointDomain, label: '域名', display: state.endpointDomain,
        clear: function () { state.endpointDomain = ''; byId('ep-domain').value = ''; state.endpointPage = 1; renderEndpoints(); }
      },
      {
        value: state.endpointMethod, label: '方法', display: state.endpointMethod,
        clear: function () { state.endpointMethod = ''; byId('ep-method').value = ''; state.endpointPage = 1; renderEndpoints(); }
      },
      {
        value: state.endpointSearch, label: '关键词', display: state.endpointSearch,
        clear: function () { state.endpointSearch = ''; byId('ep-search').value = ''; state.endpointPage = 1; renderEndpoints(); }
      }
    ], function () {
      state.endpointDomain = ''; state.endpointMethod = ''; state.endpointSearch = '';
      state.endpointPage = 1;
      byId('ep-domain').value = ''; byId('ep-method').value = ''; byId('ep-search').value = '';
      renderEndpoints();
    });
    var exportButton = byId('endpoints-export');
    if (exportButton) {
      exportButton.textContent = '导出当前筛选结果（' + total + ' 个端点）';
      exportButton.disabled = total === 0;
    }
  }

  // ----------------------------------------------------------- hosts

  var hostColumns = [
    { key: 'value', label: '主机', width: '260px' },
    { key: 'kind', label: '类型', width: '110px' },
    { key: 'registrable', label: '可注册域', width: '180px' },
    { key: 'suffix', label: '公共后缀', width: '130px' },
    { key: 'status', label: '后缀状态', width: '120px' },
    { key: 'occurrences', label: '出现次数', width: '90px', numeric: true },
    { key: 'originLabel', label: '数据来源', width: '130px' },
    { key: 'sources', label: '来源证据', width: '90px', numeric: true }
  ];

  function hostSortValue(row, key) {
    if (key === 'sources') return row.sources.length;
    if (key === 'kind') return HOST_KIND_ORDER.indexOf(row.kind);
    if (key === 'occurrences') return row.occurrences;
    return row[key];
  }

  function filterHosts() {
    var query = state.hostSearch.trim().toLowerCase();
    return hostRows.filter(function (row) {
      if (state.hostKind && row.kind !== state.hostKind) return false;
      if (!query) return true;
      var haystack = [
        row.value, row.registrable, row.suffix, row.status, row.originLabel,
        row.attributes.join(' ')
      ].join(' ');
      if (haystack.toLowerCase().indexOf(query) !== -1) return true;
      return row.sources.some(function (source) {
        return (source.url + ' ' + source.raw + ' ' + source.associated + ' ' + source.note)
          .toLowerCase().indexOf(query) !== -1;
      });
    });
  }

  function renderHosts() {
    syncControls({
      'host-kind': state.hostKind,
      'host-group': state.hostGroup,
      'host-search': state.hostSearch
    });
    ensureSortable('hosts', byId('hosts-table'), hostColumns, function () {
      state.hostPage = 1;
      renderHosts();
    });

    var rows = sortRows('hosts', filterHosts(), hostSortValue);
    if (state.hostGroup === 'registrable') {
      // Group by registrable domain (falling back to the value itself for an
      // IP or an internal host, which has no registrable domain).
      rows = rows.slice().sort(function (left, right) {
        var byGroup = compareReportValues(left.groupKey, right.groupKey);
        if (byGroup) return byGroup;
        return compareReportValues(left.value, right.value);
      });
    }

    var total = rows.length;
    var totalPages = Math.max(1, Math.ceil(total / DEFAULT_PAGE_SIZE));
    state.hostPage = Math.min(Math.max(1, state.hostPage), totalPages);
    var start = (state.hostPage - 1) * DEFAULT_PAGE_SIZE;
    var pageRows = rows.slice(start, start + DEFAULT_PAGE_SIZE);

    var body = byId('hosts-body');
    clear(body);
    if (pageRows.length === 0) {
      body.appendChild(h('tr', null, h('td', {
        colspan: String(hostColumns.length), class: 'empty',
        text: hostRows.length === 0 ? '本次未发现主机' : '没有符合当前筛选条件的主机'
      })));
    }
    var lastGroup = null;
    pageRows.forEach(function (row) {
      if (state.hostGroup === 'registrable' && row.groupKey !== lastGroup) {
        lastGroup = row.groupKey;
        var members = rows.filter(function (candidate) { return candidate.groupKey === row.groupKey; });
        body.appendChild(h('tr', { class: 'group-row' }, h('td', { colspan: String(hostColumns.length) }, [
          h('span', { class: 'group-title', text: row.groupKey }),
          h('span', { class: 'muted', text: ' （' + members.length + ' 个主机）' })
        ])));
      }
      var tr = h('tr', { tabindex: '0', class: 'clickable-row', 'aria-label': '打开主机详情 ' + row.value });
      append(tr, [
        h('td', { class: 'value-cell' }, [
          h('code', { text: row.value }),
          copyButton('复制', function () { return row.value; })
        ]),
        h('td', null, h('span', { class: 'sev ' + (row.kind === 'domain' ? 'low' : row.kind === 'internal_host' ? 'medium' : 'info'), text: hostKindLabel(row.kind) })),
        h('td', { class: 'muted', text: row.registrable || '—' }),
        h('td', { class: 'muted', text: row.suffix || '—' }),
        h('td', { class: 'muted', text: hostStatusLabel(row.status) }),
        h('td', { text: String(row.occurrences) }),
        h('td', { text: row.originLabel }),
        h('td', { text: String(row.sources.length) })
      ]);
      openOnActivate(tr, function () { openHost(row); });
      body.appendChild(tr);
    });

    var hosts = summary.hosts || {};
    byId('hosts-count').textContent = total === 0
      ? '0 个主机'
      : (start + 1) + '-' + (start + pageRows.length) + ' / ' + total + ' 个主机 · 内容发现 ' +
        (hosts.contentTotal || 0) + ' · 扫描关联 ' + (hosts.scanTotal || 0) +
        ' · 两类重合 ' + (hosts.correlated || 0);
    renderPagination(byId('hosts-pagination'), state.hostPage, totalPages, function (page) {
      state.hostPage = page;
      renderHosts();
    });
    renderChips(byId('host-chips'), [
      {
        value: state.hostKind, label: '类型', display: hostKindLabel(state.hostKind),
        clear: function () { state.hostKind = ''; byId('host-kind').value = ''; state.hostPage = 1; renderHosts(); }
      },
      {
        value: state.hostSearch, label: '关键词', display: state.hostSearch,
        clear: function () { state.hostSearch = ''; byId('host-search').value = ''; state.hostPage = 1; renderHosts(); }
      }
    ], function () {
      state.hostKind = '';
      state.hostSearch = '';
      state.hostPage = 1;
      byId('host-kind').value = '';
      byId('host-search').value = '';
      renderHosts();
    });
    var exportButton = byId('hosts-export');
    if (exportButton) {
      exportButton.textContent = '导出当前筛选结果（' + total + ' 个主机）';
      exportButton.disabled = total === 0;
    }
  }

  function openHost(row) {
    var nodes = [
      h('div', { class: 'drawer-meta' }, [
        h('span', { class: 'sev ' + (row.kind === 'domain' ? 'low' : row.kind === 'internal_host' ? 'medium' : 'info'), text: hostKindLabel(row.kind) }),
        h('code', { text: row.value }),
        row.originLabel ? h('span', { class: 'muted', text: row.originLabel }) : null,
        h('span', { class: 'sev pending', text: hostStatusLabel(row.status) })
      ]),
      section('分类与层级', [
        h('div', { class: 'drawer-row' }, [h('span', { class: 'muted', text: '主机类型：' }), h('span', { text: hostKindLabel(row.kind) })]),
        h('div', { class: 'drawer-row' }, [h('span', { class: 'muted', text: '可注册域：' }), h('code', { text: row.registrable || '未识别（不伪造层级）' })]),
        h('div', { class: 'drawer-row' }, [h('span', { class: 'muted', text: '公共后缀：' }), h('code', { text: row.suffix || '—' })]),
        h('div', { class: 'drawer-row' }, [h('span', { class: 'muted', text: '子域：' }), h('code', { text: row.subdomain || '—' })]),
        h('div', { class: 'drawer-row' }, [h('span', { class: 'muted', text: '后缀状态：' }), h('span', { text: hostStatusLabel(row.status) })]),
        row.zone ? h('div', { class: 'drawer-row' }, [h('span', { class: 'muted', text: 'IPv6 区域：' }), h('code', { text: row.zone })]) : null,
        row.attributes.length ? h('div', { class: 'drawer-row' }, [
          h('span', { class: 'muted', text: '地址属性：' })
        ].concat(row.attributes.map(function (attribute) {
          return h('span', { class: 'sev info', text: hostAttributeLabel(attribute) });
        }))) : null,
        h('div', { class: 'drawer-row' }, [
          h('span', { class: 'muted', text: '出现次数：' }),
          h('span', { text: String(row.occurrences) }),
          h('span', { class: 'muted', text: '来源证据 ' + row.sources.length + ' 条' })
        ]),
        h('p', { class: 'layer-note', text: '主机属性只说明该值在代码或扫描记录中出现，未做 DNS 查询与连通性探测，不代表可访问资产；地址属性不构成“公网可路由”的判断。' })
      ]),
      section('来源证据（' + row.sources.length + ' 条）',
        row.sources.map(function (source, index) { return hostSourceEntry(row, source, index); })),
      section('操作', [
        h('div', { class: 'inline-actions' }, [
          copyButton('复制主机值', function () { return row.value; }),
          copyButton('复制证据清单', function () { return hostEvidenceText(row); })
        ])
      ])
    ];
    openDrawer(row.value, nodes.filter(Boolean));
  }

  function hostSourceEntry(row, source, index) {
    var href = safeHref(source.url);
    var location = source.url + (source.line ? ':' + source.line + ':' + source.column : '');
    return h('details', { class: 'source-entry', open: index === 0 ? 'open' : null }, [
      h('summary', null, [
        h('span', { class: 'source-index', text: '#' + (index + 1) }),
        href
          ? h('a', { href: href, target: '_blank', rel: 'noopener noreferrer' }, h('code', { text: source.url }))
          : h('code', { text: source.url || '—' }),
        source.line ? h('span', { class: 'muted', text: '行 ' + source.line + ' 列 ' + source.column }) : null,
        h('span', { class: 'sev info', text: HOST_METHOD_LABELS[source.method] || source.method || '未知方式' }),
        source.note ? h('span', { class: 'muted', text: hostNoteLabel(source.note) }) : null
      ]),
      h('div', { class: 'source-body' }, [
        h('div', { class: 'drawer-row' }, [
          h('span', { class: 'muted', text: '原始值：' }),
          h('code', { text: source.raw || row.value })
        ]),
        source.associated ? h('div', { class: 'drawer-row' }, [
          h('span', { class: 'muted', text: '所属 URL：' }),
          h('code', { text: source.associated })
        ]) : null,
        h('div', { class: 'drawer-row' }, [
          h('span', { class: 'muted', text: '定位：' }),
          h('code', { text: location || '—' })
        ]),
        contextBlock(source)
      ])
    ]);
  }

  function hostEvidenceText(row) {
    var lines = [
      '主机: ' + row.value,
      '类型: ' + hostKindLabel(row.kind),
      '可注册域: ' + (row.registrable || '未识别'),
      '公共后缀: ' + (row.suffix || '—'),
      '后缀状态: ' + hostStatusLabel(row.status),
      '数据来源: ' + row.originLabel,
      '出现次数: ' + row.occurrences,
      '证据:'
    ];
    row.sources.forEach(function (source) {
      lines.push('  ' + (HOST_METHOD_LABELS[source.method] || source.method) + ' | ' +
        source.raw + ' | ' + source.url + (source.line ? ':' + source.line + ':' + source.column : '') +
        (source.note ? ' | ' + hostNoteLabel(source.note) : ''));
    });
    return lines.join('\n');
  }

  function exportHosts() {
    var rows = sortRows('hosts', filterHosts(), hostSortValue);
    var csvText = csv.build(
      ['主机', '类型', '可注册域', '公共后缀', '子域', '后缀状态', '地址属性', '出现次数', '数据来源', '来源证据数', '首个来源URL', '首个来源行', '提取方式'],
      rows.map(function (row) {
        var first = row.sources[0] || {};
        return [
          row.value, hostKindLabel(row.kind), row.registrable, row.suffix, row.subdomain,
          hostStatusLabel(row.status),
          row.attributes.map(hostAttributeLabel).join(' '),
          row.occurrences, row.originLabel, row.sources.length,
          first.url || '', first.line || '',
          HOST_METHOD_LABELS[first.method] || first.method || ''
        ];
      })
    );
    var host = summary.targetHost || text(data.target);
    download(csv.fileName('hosts', host, rows.length), csvText);
    toast('已导出 ' + rows.length + ' 个主机（当前筛选条件，非仅当前页）');
  }

  // -------------------------------------------------------- routes/params

  var PROBE_LABELS = {
    server: '服务端真实页面', static: '纯前端路由', error: '探测失败', unknown: '无基准'
  };
  var EXTRACTOR_LABELS = {
    cdp: 'CDP 运行时', 'cdp-runtime': 'CDP 运行时', ast: 'AST', regex: '正则',
    prefix: '前缀拼接'
  };
  var routeColumns = [
    { key: 'url', label: '路由路径' },
    { key: 'extractor', label: '提取方式', width: '120px' },
    { key: 'evidence', label: '证据', width: '100px' },
    { key: 'source', label: '来源', width: '280px' },
    { key: 'probe', label: '探测结果', width: '140px' }
  ];
  var issueColumns = [
    { key: 'code', label: '代码', width: '160px' },
    { key: 'stage', label: '阶段', width: '110px' },
    { key: 'url', label: 'URL' },
    { key: 'message', label: '消息' },
    { key: 'retryable', label: '可重试', width: '90px' }
  ];

  function renderRoutes() {
    ensureSortable('routes', byId('routes-table'), routeColumns, function () { renderRoutes(); });
    var rows = filterRoutes().map(function (route) {
      return {
        url: text(route.url),
        extractor: EXTRACTOR_LABELS[text(route.source)] || text(route.source) || '—',
        evidence: text(route.evidence) || 'static',
        source: text(route.source_url) || '—',
        probe: PROBE_LABELS[text(route.probe)] || '未探测',
        raw: route
      };
    });
    rows = sortRows('routes', rows, function (row, key) { return row[key]; });

    var body = byId('routes-body');
    clear(body);
    if (rows.length === 0) {
      body.appendChild(h('tr', null, h('td', {
        colspan: '5', class: 'empty',
        text: endpoints.some(function (endpoint) { return text(endpoint.type) === 'route'; })
          ? '没有符合当前筛选条件的路由' : '本次未采集到前端路由'
      })));
      byId('routes-count').textContent = '0 条路由';
      renderParams();
      return;
    }
    rows.forEach(function (row) {
      body.appendChild(h('tr', null, [
        h('td', { class: 'path-cell' }, h('code', { text: row.url })),
        h('td', { text: row.extractor }),
        h('td', null, h('span', {
          class: 'sev ' + (row.evidence === 'runtime' ? 'runtime' : row.evidence === 'full-url' ? 'high' : 'info'),
          text: row.evidence
        })),
        h('td', { class: 'source-cell' }, h('code', { text: row.source })),
        h('td', { text: row.probe })
      ]));
    });
    byId('routes-count').textContent = plural(rows.length, '条路由');
    renderParams();
  }

  function renderParams() {
    var container = byId('params-list');
    var query = state.paramSearch.trim().toLowerCase();
    var names = params.filter(function (name) { return !query || name.toLowerCase().indexOf(query) !== -1; });
    clear(container);
    byId('params-count').textContent = params.length === 0
      ? '本次未提取到参数名'
      : '显示 ' + names.length + ' / ' + params.length + ' 个参数名';
    if (names.length === 0) {
      container.appendChild(h('p', { class: 'empty', text: params.length === 0 ? '本次未提取到参数名' : '没有匹配的参数名' }));
      return;
    }
    names.forEach(function (name) {
      container.appendChild(h('code', { class: 'param-chip', text: name }));
    });
  }

  // ------------------------------------------------------------ resources

  function renderResources() {
    ensureSortable('resources', byId('resources-table'), resourceColumns, function () {
      state.resourcePage = 1;
      renderResources();
    });

    var rows = resources.map(function (resource) {
      return {
        raw: resource,
        type: text(resource.type),
        url: text(resource.url),
        status: resource.status_code || 0,
        size: resource.size || 0,
        local: text(resource.local_path)
      };
    });
    rows = sortRows('resources', rows, function (row, key) { return row[key]; });
    var total = rows.length;
    var totalPages = Math.max(1, Math.ceil(total / DEFAULT_PAGE_SIZE));
    state.resourcePage = Math.min(Math.max(1, state.resourcePage), totalPages);
    var start = (state.resourcePage - 1) * DEFAULT_PAGE_SIZE;
    var pageRows = rows.slice(start, start + DEFAULT_PAGE_SIZE);
    var body = byId('resources-body');
    clear(body);
    if (pageRows.length === 0) {
      body.appendChild(h('tr', null, h('td', { colspan: '5', class: 'empty', text: '本次未采集到资源' })));
    }
    pageRows.forEach(function (row) {
      var href = safeHref(row.url);
      body.appendChild(h('tr', null, [
        h('td', { text: row.type || '—' }),
        h('td', { class: 'url-cell' }, href
          ? h('a', { href: href, target: '_blank', rel: 'noopener noreferrer' }, h('code', { text: row.url }))
          : h('code', { text: row.url || '—' })),
        h('td', { text: row.status ? String(row.status) : '未响应' }),
        h('td', { text: String(row.size) }),
        h('td', { class: 'source-cell' }, h('code', { text: row.local || '—' }))
      ]));
    });
    byId('resources-count').textContent = total === 0 ? '0 个资源'
      : (start + 1) + '-' + (start + pageRows.length) + ' / ' + total + ' 个资源';
    renderPagination(byId('resources-pagination'), state.resourcePage, totalPages, function (page) {
      state.resourcePage = page;
      renderResources();
    });

    var resourceSummary = summary.resources || {};
    charts.barList(byId('resource-types'), (resourceSummary.types || []).map(function (bucket) {
      return { key: bucket.key, label: bucket.label || bucket.key, count: bucket.count };
    }), { unit: ' 个资源', emptyText: '本次未采集到资源' });
    charts.barList(byId('resource-status'), (resourceSummary.status || []).map(function (bucket) {
      return { key: bucket.key, label: bucket.label || bucket.key, count: bucket.count };
    }), { unit: ' 个资源', emptyText: '本次未采集到资源' });
    var notes = byId('resource-notes');
    clear(notes);
    (resourceSummary.notes || []).forEach(function (note) {
      notes.appendChild(h('li', { text: note }));
    });
  }

  // ---------------------------------------------------------- diagnostics

  function renderDiagnostics() {
    ensureSortable('issues', byId('issues-table'), issueColumns, function () { renderDiagnostics(); });
    var rows = sortRows('issues', issues.map(function (issue) {
      return {
        code: text(issue.code) || '—',
        stage: text(issue.stage) || '—',
        url: text(issue.url),
        message: text(issue.message),
        retryable: issue.retryable ? '可重试' : '不可重试'
      };
    }), function (row, key) { return row[key]; });

    var body = byId('issues-body');
    clear(body);
    if (rows.length === 0) {
      body.appendChild(h('tr', null, h('td', { colspan: '5', class: 'empty', text: '本次扫描没有诊断信息' })));
    }
    rows.forEach(function (issue) {
      var href = safeHref(issue.url);
      body.appendChild(h('tr', null, [
        h('td', null, h('code', { text: issue.code })),
        h('td', { text: issue.stage }),
        h('td', { class: 'url-cell' }, href
          ? h('a', { href: href, target: '_blank', rel: 'noopener noreferrer' }, h('code', { text: issue.url }))
          : h('code', { text: issue.url || '—' })),
        h('td', { text: issue.message }),
        h('td', { text: issue.retryable })
      ]));
    });
    byId('issues-count').textContent = plural(rows.length, '条诊断记录');

    var issueSummary = summary.issues || {};
    charts.barList(byId('issue-codes'), (issueSummary.codes || []).map(function (bucket) {
      return { key: bucket.key, label: bucket.label || bucket.key, count: bucket.count };
    }), { unit: ' 条', labelLimit: 24, emptyText: '没有诊断分类' });
    charts.barList(byId('issue-stages'), (issueSummary.stages || []).map(function (bucket) {
      return { key: bucket.key, label: bucket.label || bucket.key, count: bucket.count };
    }), { unit: ' 条', emptyText: '没有诊断分类' });

    var notes = byId('issue-notes');
    clear(notes);
    notes.appendChild(h('li', { text: '诊断信息只记录非致命问题；出现诊断不代表扫描失败，但会影响对应资源的完整性。' }));
    if (summary.browserNote) {
      notes.appendChild(h('li', { text: summary.browserNote }));
    }
    (summary.resources && summary.resources.notes ? summary.resources.notes : []).forEach(function (note) {
      notes.appendChild(h('li', { text: note }));
    });
  }

  // -------------------------------------------------------------- drawer

  function drawerOpen() { return byId('drawer').classList.contains('open'); }

  function closeDrawer() {
    var drawer = byId('drawer');
    drawer.classList.remove('open');
    drawer.setAttribute('aria-hidden', 'true');
    clear(byId('drawer-body'));
  }

  function openDrawer(title, nodes) {
    byId('drawer-title').textContent = title;
    var body = clear(byId('drawer-body'));
    nodes.forEach(function (node) { body.appendChild(node); });
    var drawer = byId('drawer');
    drawer.classList.add('open');
    drawer.setAttribute('aria-hidden', 'false');
    byId('drawer-close').focus();
  }

  function section(title, children, extraClass) {
    return h('section', { class: 'drawer-section' + (extraClass ? ' ' + extraClass : '') }, [
      h('h3', { class: 'drawer-section-title', text: title })
    ].concat(children));
  }

  // normalizeContextLines maps a context-line record onto the fields the
  // renderer reads. Aggregated sources carry the list as `context`, endpoints
  // as `context_lines`; both spellings and the Go field spelling are accepted,
  // matching how the other normalizers in this report behave.
  function normalizeContextLines(source) {
    if (!source) return [];
    var lines = source.context || source.context_lines || source.ContextLines || [];
    return lines.map(function (line) {
      return {
        lineNumber: pick(line, 'line_number', 'LineNumber') || 0,
        content: text(pick(line, 'content', 'Content')),
        matchStart: pick(line, 'match_start', 'MatchStart'),
        matchEnd: pick(line, 'match_end', 'MatchEnd')
      };
    });
  }

  function contextBlock(source) {
    var lines = normalizeContextLines(source);
    if (lines.length === 0) {
      return h('p', { class: 'muted', text: '未保留源码上下文' });
    }
    var pre = h('pre', { class: 'context-code' });
    lines.forEach(function (line) {
      var code = h('span', { class: 'line-content' });
      if (typeof line.matchStart === 'number' && typeof line.matchEnd === 'number' &&
          line.matchStart >= 0 && line.matchEnd > line.matchStart) {
        var chars = Array.from(line.content);
        append(code, [
          chars.slice(0, line.matchStart).join(''),
          h('mark', { text: chars.slice(line.matchStart, line.matchEnd).join('') }),
          chars.slice(line.matchEnd).join('')
        ]);
      } else {
        code.textContent = line.content;
      }
      pre.appendChild(h('span', { class: 'line' }, [
        h('span', { class: 'line-num', text: String(line.lineNumber) }),
        code
      ]));
    });
    return pre;
  }

  function sourceEntry(source, group, index) {
    var href = safeHref(source.url);
    var position = text(source.url) + (source.line ? ':' + source.line + ':' + (source.column || 0) : '');
    var copy = copyButton('复制证据', function () { return evidenceText(group, source); });
    return h('details', { class: 'source-entry', open: index === 0 ? 'open' : null }, [
      h('summary', null, [
        h('span', { class: 'source-index', text: '#' + (index + 1) }),
        href
          ? h('a', { href: href, target: '_blank', rel: 'noopener noreferrer' }, h('code', { text: text(source.url) }))
          : h('code', { text: text(source.url) || '—' }),
        source.line ? h('span', { class: 'muted', text: '行 ' + source.line + ' 列 ' + (source.column || 0) }) : null,
        source.vendor ? h('span', { class: 'sev vendor', text: 'vendor' }) : null
      ]),
      h('div', { class: 'source-body' }, [
        h('div', { class: 'drawer-row' }, [
          h('span', { class: 'muted', text: '定位：' }),
          h('code', { text: position || '—' }),
          copy
        ]),
        source.ai ? h('div', { class: 'drawer-row' }, [
          h('span', { class: 'muted', text: '该命中的 AI 评估：' }),
          h('span', { class: 'sev ai-badge', text: text(source.ai.rating) }),
          h('span', { text: text(source.ai.reason) })
        ]) : null,
        contextBlock(source)
      ])
    ]);
  }

  function evidenceText(group, source) {
    var lines = [
      '规则: ' + group.ruleName + ' (' + group.ruleId + ')',
      '编号: ' + group.id,
      '等级: ' + severityLabel(group.severity) + ' (' + group.severity + ')',
      '分类: ' + group.categoryLabel,
      '核查状态: ' + (group.confirmation || '待人工验证'),
      '完整值: ' + group.value,
      '来源: ' + text(source && source.url) + (source && source.line ? ':' + source.line + ':' + (source.column || 0) : '')
    ];
    if (source && source.context && source.context.length) {
      lines.push('上下文:');
      source.context.forEach(function (line) {
        lines.push('  ' + (pick(line, 'line_number', 'LineNumber') || '') + ' | ' + text(pick(line, 'content', 'Content')));
      });
    }
    return lines.join('\n');
  }

  function openGroup(group) {
    if (!group) return;
    var reportFile = group.category === 'sensitive' ? '敏感信息报告.html' : 'URL报告.html';
    var nodes = [
      h('div', { class: 'drawer-meta' }, [
        severityBadge(group.severity),
        h('span', { class: 'muted', text: group.categoryLabel }),
        h('code', { text: group.id }),
        h('span', { class: 'sev pending', text: group.confirmation || '待人工验证' })
      ]),
      section('规则命中', [
        h('div', { class: 'drawer-row' }, [h('span', { class: 'muted', text: '规则名称：' }), h('span', { text: group.ruleName })]),
        h('div', { class: 'drawer-row' }, [h('span', { class: 'muted', text: '规则编号：' }), h('code', { text: group.ruleId })]),
        h('div', { class: 'drawer-row' }, [h('span', { class: 'muted', text: '命中等级：' }), severityBadge(group.severity), h('span', { class: 'muted', text: '（规则定义等级，非人工确认结论）' })]),
        group.group ? h('div', { class: 'drawer-row' }, [h('span', { class: 'muted', text: '规则分组：' }), h('span', { text: group.group })]) : null,
        h('div', { class: 'drawer-row' }, [h('span', { class: 'muted', text: '命中次数：' }), h('span', { text: String(group.hits) }), h('span', { class: 'muted', text: '来源位置 ' + (group.sources || []).length + ' 处' })])
      ]),
      section('完整发现值', [
        h('div', { class: 'value-block' }, [
          h('pre', { class: 'value-pre', text: group.value }),
          copyButton('复制发现值', function () { return group.value; })
        ])
      ]),
      // The three assessment layers stay visually separate: a rule hit is not
      // an AI verdict and neither is a human confirmation.
      group.ai ? section('AI 辅助评估', [
        h('p', { class: 'layer-note', text: '来自模型的可选辅助判断，仅供参考，不代表已确认。' }),
        h('div', { class: 'drawer-row' }, [h('span', { class: 'muted', text: '评级：' }), h('span', { class: 'sev ai-badge', text: text(group.ai.rating) })]),
        h('div', { class: 'drawer-row' }, [h('span', { class: 'muted', text: '理由：' }), h('span', { text: text(group.ai.reason) || '—' })]),
        h('div', { class: 'drawer-row' }, [h('span', { class: 'muted', text: '建议：' }), h('span', { text: text(group.ai.suggestion) || '—' })])
      ], 'ai-section') : section('AI 辅助评估', [
        h('p', { class: 'muted', text: '本次扫描未为此发现生成 AI 评估（未启用 -ai 或该发现未送入模型）。' })
      ]),
      section('人工核查建议', [
        h('p', { class: 'layer-note', text: '以下为按规则类型给出的下一步动作，不是漏洞结论。' }),
        h('p', { text: group.verify })
      ]),
      section('来源位置与源码上下文（' + (group.sources || []).length + ' 处）',
        (group.sources || []).map(function (source, index) { return sourceEntry(source, group, index); })),
      section('分项报告', [
        h('p', null, safeHref(reportFile)
          ? h('a', { href: reportFile, class: 'drawer-link', text: '在分项报告中查看同类记录 →' })
          : h('span', { class: 'muted', text: '无可跳转的分项报告' }))
      ])
    ];
    openDrawer(group.ruleName + ' · ' + group.id, nodes.filter(Boolean));
  }

  function openEndpoint(endpoint) {
    var method = endpointMethod(endpoint);
    var params = endpointParams(endpoint);
    var packet = text(endpoint.packet);
    var spec = endpoint.spec || null;
    var ai = (endpoint.template && endpoint.template.ai) || null;

    var paramRows = params.length === 0
      ? [h('p', { class: 'muted', text: '未提取到参数：请求体或查询串没有在源码中被静态解析出来，需要在测试时人工补齐。' })]
      : params.map(function (row) {
        return h('div', { class: 'drawer-row' }, [
          h('span', { class: 'param-origin', text: row.origin === 'query' ? 'query' : row.origin === 'body' ? 'body' : 'response' }),
          h('code', { text: row.key }),
          h('span', { class: 'muted', text: row.value ? '默认值 ' + row.value : '未取到默认值' }),
          row.evidence ? h('span', { class: 'sev ' + (row.evidence === 'literal' ? 'runtime' : 'info'), text: row.evidence }) : null
        ]);
      });

    var nodes = [
      h('div', { class: 'drawer-meta' }, [
        h('span', { class: 'method-tag ' + (method === UNRESOLVED_METHOD ? 'unknown' : method.toLowerCase()), text: method }),
        h('code', { text: endpointPath(endpoint) }),
        endpoint.authorized ? h('span', { class: 'sev runtime', text: '授权范围内' }) : h('span', { class: 'sev info', text: '未授权探测' })
      ]),
      section('端点信息', [
        h('div', { class: 'drawer-row' }, [h('span', { class: 'muted', text: '方法：' }), h('span', { text: method }), method === UNRESOLVED_METHOD ? h('span', { class: 'muted', text: '（源码中未记录方法，未默认补为 GET）' }) : null]),
        h('div', { class: 'drawer-row' }, [h('span', { class: 'muted', text: '解析后 URL：' }), h('code', { text: text(endpoint.url) || '未解析' })]),
        h('div', { class: 'drawer-row' }, [h('span', { class: 'muted', text: '源码中的写法：' }), h('code', { text: text(endpoint.raw) || '—' })]),
        h('div', { class: 'drawer-row' }, [h('span', { class: 'muted', text: '证据强度：' }), h('span', { text: text(endpoint.evidence) || 'static' }), h('span', { class: 'muted', text: '提取方式：' + (EXTRACTOR_LABELS[text(endpoint.source)] || text(endpoint.source) || '—') })]),
        h('div', { class: 'drawer-row' }, [h('span', { class: 'muted', text: '探测状态：' }), h('span', { text: endpoint.status_code ? String(endpoint.status_code) : '未探测' })]),
        h('div', { class: 'drawer-row' }, [h('span', { class: 'muted', text: '来源：' }), safeHref(endpoint.source_url)
          ? h('a', { href: safeHref(endpoint.source_url), target: '_blank', rel: 'noopener noreferrer' }, h('code', { text: text(endpoint.source_url) }))
          : h('code', { text: text(endpoint.source_url) || '—' }),
          endpoint.line ? h('span', { class: 'muted', text: '行 ' + endpoint.line + ' 列 ' + (endpoint.column || 0) }) : null])
      ]),
      section('参数（' + params.length + ' 个）', paramRows),
      spec && (spec.content_type || spec.base_url) ? section('请求规格', [
        spec.base_url ? h('div', { class: 'drawer-row' }, [h('span', { class: 'muted', text: 'BaseURL：' }), h('code', { text: spec.base_url }), h('span', { class: 'muted', text: text(spec.base_url_kind) })]) : null,
        spec.content_type ? h('div', { class: 'drawer-row' }, [h('span', { class: 'muted', text: 'Content-Type：' }), h('code', { text: spec.content_type }), h('span', { class: 'muted', text: text(spec.content_type_evidence) })]) : null
      ]) : null,
      packet ? section('请求包（静态重建，未实际发送）', [
        h('p', { class: 'layer-note', text: '该请求由源码静态重建，用于人工测试，JsOwl 没有发送过它。' }),
        h('pre', { class: 'packet-pre', text: packet }),
        copyButton('复制请求包', function () { return packet; })
      ]) : section('请求包', [
        h('p', { class: 'muted', text: '未能重建请求包：源码中没有可用的参数或方法信息。' })
      ]),
      ai ? section('AI 辅助评估', [
        h('p', { class: 'layer-note', text: '模型对请求包完整性与真实性的参考意见。' }),
        h('pre', { class: 'packet-pre', text: JSON.stringify(ai, null, 2) })
      ], 'ai-section') : null,
      endpoint.context_lines && endpoint.context_lines.length
        ? section('匹配上下文', [contextBlock(endpoint)])
        : null
    ];
    openDrawer(endpointPath(endpoint) || '端点详情', nodes.filter(Boolean));
  }

  // ------------------------------------------------------------- printing

  function printGroups() {
    var all = groups;
    if (state.printScope === 'full') return { rows: all, truncated: false };
    return { rows: all.slice(0, PRINT_SOFT_CAP), truncated: all.length > PRINT_SOFT_CAP };
  }

  function printParagraph(textValue) { return h('p', { text: textValue }); }

  function printTable(header, rows, extraClass) {
    return h('table', { class: 'print-table' + (extraClass ? ' ' + extraClass : '') }, [
      h('thead', null, h('tr', null, header.map(function (label) {
        return h('th', { scope: 'col', text: label });
      }))),
      h('tbody', null, rows)
    ]);
  }

  function printKeyFindings() {
    var keys = summary.key || [];
    if (keys.length === 0) {
      return printParagraph('本次扫描未命中任何规则，因此没有重点发现。这不等同于“未发现风险”，只说明当前规则集没有命中。');
    }
    if (severityRows.every(function (row) { return severityRank(row.severity) <= 2; })) {
      return printParagraph('本次扫描未命中 high / critical 等级规则，以下为全部命中中等级最高的记录，请按实际业务判断是否需要处理。');
    }
    return null;
  }

  function buildPrintDoc() {
    var scope = printGroups();
    var container = clear(byId('print-doc'));
    var sections = [];

    // 1. 封面
    sections.push(h('section', { class: 'print-cover' }, [
      h('h1', { text: 'JsOwl JavaScript 信息收集与敏感信息扫描报告' }),
      h('p', { class: 'print-target', text: summary.target || text(data.target) }),
      h('dl', { class: 'print-meta' }, [
        h('dt', { text: '扫描模式' }), h('dd', { text: text(summary.modeLabel) || '未记录' }),
        h('dt', { text: '扫描开始' }), h('dd', { text: summary.startedAt || '本次结果未记录扫描开始时间' }),
        h('dt', { text: '扫描结束' }), h('dd', { text: summary.finishedAt || '本次结果未记录扫描结束时间' }),
        h('dt', { text: '报告生成时间' }), h('dd', { text: text(summary.generatedAt) }),
        h('dt', { text: '报告说明' }), h('dd', { text: '本报告由 JsOwl 自动生成，未包含人工确认结论。' })
      ]),
      h('p', { class: 'print-warning', text: '本报告含完整敏感数据，未做脱敏处理，请严格控制访问范围。' })
    ]));

    // 2. 报告摘要
    sections.push(h('section', null, [
      h('h2', { text: '一、报告摘要' }),
      printParagraph('本次对目标 ' + (summary.target || text(data.target)) + ' 完成 JavaScript 信息收集与敏感信息规则匹配：' +
        '采集资源 ' + text((summary.resources || {}).total || 0) + ' 个，识别 API 端点 ' +
        text(metricValue('endpoints')) + ' 个、前端路由 ' + text(metricValue('routes')) + ' 个，' +
        '提取参数名 ' + text(metricValue('params')) + ' 个，命中规则 ' + groups.length + ' 条聚合发现（原始命中 ' +
        rawHits.length + ' 次）。'),
      printParagraph('全部发现的核查状态均为「待人工验证」：报告呈现的是规则命中与可选的 AI 辅助评估，不包含人工确认的漏洞结论，也没有给出 CVSS 评分。')
    ]));

    // 3. 目标、范围与方法
    sections.push(h('section', null, [
      h('h2', { text: '二、扫描目标、范围与方法' }),
      printTable(['项目', '内容'], [
        h('tr', null, [h('td', { text: '目标' }), h('td', { text: summary.target || '—' })]),
        h('tr', null, [h('td', { text: '扫描模式' }), h('td', { text: text(summary.modeLabel) || '未记录' })]),
        h('tr', null, [h('td', { text: 'User-Agent' }), h('td', { text: text(summary.userAgent) || '未记录' })]),
        h('tr', null, [h('td', { text: '采集方式' }), h('td', { text: '静态下载 JavaScript 并做正则/AST 分析；启用浏览器阶段时叠加 CDP 运行时观测。' })]),
        h('tr', null, [h('td', { text: '浏览器阶段' }), h('td', { text: summary.browserUsed ? '已启用' : '未启用或降级' + (summary.browserNote ? '：' + summary.browserNote : '') })]),
        h('tr', null, [h('td', { text: '范围说明' }), h('td', { text: text(summary.attackNote) })])
      ]),
      printParagraph('边界说明：JsOwl 负责“采集与规则匹配”，不代替人工测试。报告中的攻击面来自自动发现，可能存在未采集到的资源与端点；发现的规则命中需要人工确认是否真实、是否可利用。本报告不构成完整的渗透测试结论。')
    ]));

    // 4. 发现与攻击面统计
    var severityTableRows = severityRows.length ? severityRows.map(function (row) {
      return h('tr', null, [
        h('td', { text: severityLabel(row.severity) + '（' + row.severity + '）' }),
        h('td', { text: String(row.groups) }),
        h('td', { text: String(row.hits) }),
        h('td', { text: String(row.domains) })
      ]);
    }) : [h('tr', null, [h('td', { colspan: '4', text: '本次扫描未命中任何规则' })])];
    sections.push(h('section', null, [
      h('h2', { text: '三、发现与攻击面统计' }),
      h('h3', { text: '3.1 风险等级分布' }),
      printTable(['等级', '聚合发现', '原始命中', '涉及域名'], severityTableRows),
      printParagraph('口径：聚合发现按 规则 + 分类 + 等级 + 完整值 合并；原始命中为规则每一次匹配。等级为规则定义等级。'),
      h('h3', { text: '3.2 攻击面指标' }),
      printTable(['指标', '数量', '统计口径'], (summary.attackMetrics || []).map(function (metric) {
        return h('tr', null, [
          h('td', { text: metric.label }),
          h('td', { text: String(metric.value) + (metric.sub ? '（' + (metric.subLabel || '小计') + ' ' + metric.sub + '）' : '') }),
          h('td', { text: metric.note })
        ]);
      })),
      h('h3', { text: '3.3 主机分布' }),
      printTable(['主机', '类型', 'API 端点', '路由', '资源', '命中'], (summary.domains || []).slice(0, 40).map(function (domain) {
        return h('tr', null, [
          h('td', { text: domain.host }),
          h('td', { text: (HOST_KIND_LABELS[domain.kind] || '未解析主机') }),
          h('td', { text: String(domain.endpoints) }),
          h('td', { text: String(domain.routes) }),
          h('td', { text: String(domain.resources) }),
          h('td', { text: String(domain.findings) })
        ]);
      })),
      (summary.domains || []).length > 40
        ? printParagraph('此处仅列出端点数量最多的 40 个主机，完整清单见交互报告的主机资产页。')
        : null,
      h('h3', { text: '3.4 主机资产' }),
      printParagraph('本节区分两类主机：内容发现（出现在 JavaScript 等被分析内容中的主机值）与扫描关联（目标、资源、端点、发现来源所属主机）。' +
        '两类使用同一套归一化与公共后缀分类规则，分别计数，不做合并汇总。发现主机不代表可访问资产：本次未做 DNS 查询与连通性探测。'),
      printTable(['类型', '内容发现', '扫描关联'], (summary.hosts && summary.hosts.metrics ? summary.hosts.metrics : []).map(function (entry) {
        return h('tr', null, [
          h('td', { text: entry.label }),
          h('td', { text: String(entry.content) }),
          h('td', { text: String(entry.scan) })
        ]);
      }).concat([
        h('tr', null, [
          h('td', { text: '合计（去重前）' }),
          h('td', { text: String((summary.hosts || {}).contentTotal || 0) }),
          h('td', { text: String((summary.hosts || {}).scanTotal || 0) })
        ])
      ])),
      h('ul', { class: 'print-sources' }, ((summary.hosts || {}).notes || []).map(function (note) {
        return h('li', { text: note });
      })),
      hostRows.length
        ? printTable(['主机', '类型', '可注册域', '后缀状态', '出现次数', '数据来源'], hostRows.slice(0, 60).map(function (row) {
          return h('tr', null, [
            h('td', { text: row.value }),
            h('td', { text: hostKindLabel(row.kind) }),
            h('td', { text: row.registrable || '—' }),
            h('td', { text: hostStatusLabel(row.status) }),
            h('td', { text: String(row.occurrences) }),
            h('td', { text: row.originLabel })
          ]);
        }))
        : printParagraph('本次未发现主机。')
    ].filter(Boolean)));

    // 5. 重点发现及证据
    var keyNodes = [];
    (summary.key || []).forEach(function (group) {
      keyNodes.push(h('div', { class: 'print-finding' }, [
        h('h3', { text: group.id + ' ' + group.ruleName + '（' + severityLabel(group.severity) + ' / ' + group.severity + '）' }),
        h('dl', { class: 'print-meta' }, [
          h('dt', { text: '规则编号' }), h('dd', { text: group.ruleId }),
          h('dt', { text: '分类' }), h('dd', { text: group.categoryLabel }),
          h('dt', { text: '命中次数' }), h('dd', { text: String(group.hits) + ' 次，涉及 ' + (group.sources || []).length + ' 处来源' }),
          h('dt', { text: '核查状态' }), h('dd', { text: group.confirmation || '待人工验证' })
        ]),
        h('p', { class: 'print-value-label', text: '完整发现值：' }),
        h('pre', { class: 'print-value', text: group.value }),
        group.ai ? h('p', { text: 'AI 辅助评估：' + text(group.ai.rating) + ' — ' + text(group.ai.reason) }) : null,
        h('p', { text: '人工核查建议：' + group.verify }),
        h('p', { class: 'print-value-label', text: '来源位置：' }),
        h('ul', { class: 'print-sources' }, (group.sources || []).map(function (source) {
          return h('li', { text: text(source.url) + (source.line ? ':' + source.line + ':' + (source.column || 0) : '') });
        })),
        (group.sources || []).length && group.sources[0].context && group.sources[0].context.length
          ? h('div', null, [h('p', { class: 'print-value-label', text: '首处来源上下文：' }), contextBlock(group.sources[0])])
          : null
      ].filter(Boolean)));
    });
    var noHigh = printKeyFindings();
    sections.push(h('section', null, [
      h('h2', { text: '四、重点发现及证据' })
    ].concat(noHigh ? [noHigh] : []).concat(keyNodes.length ? keyNodes : [
      printParagraph('本次扫描没有产生重点发现。')
    ])));

    // 6. 核查建议
    sections.push(h('section', null, [
      h('h2', { text: '五、优先核查清单' }),
      printParagraph('优先级说明：P1 = high / critical 等级规则命中，P2 = medium，P3 = low / info。优先级表示建议的查看顺序，与“是否已确认漏洞”无关。'),
      printTable(['优先级', '编号', '发现', '等级', '命中', '核查状态', '建议下一步'],
        (summary.priority || []).slice(0, 60).map(function (item) {
          return h('tr', null, [
            h('td', { text: item.level }),
            h('td', { text: item.groupId }),
            h('td', { text: item.title }),
            h('td', { text: severityLabel(item.severity) }),
            h('td', { text: String(item.hits) }),
            h('td', { text: item.status }),
            h('td', { text: item.next })
          ]);
        }))
    ]));

    // 7. 附录与诊断
    var appendixRows = scope.rows.map(function (group) {
      return h('tr', null, [
        h('td', { text: group.id }),
        h('td', { text: severityLabel(group.severity) }),
        h('td', { text: group.ruleName }),
        h('td', { text: group.categoryLabel }),
        h('td', { text: group.value }),
        h('td', { text: String((group.sources || []).length) }),
        h('td', { text: String(group.hits) }),
        h('td', { text: group.confirmation || '待人工验证' })
      ]);
    });
    sections.push(h('section', null, [
      h('h2', { text: '六、附录与诊断摘要' }),
      h('h3', { text: '6.1 聚合发现清单' })
    ].concat(
      scope.truncated ? [h('p', {
        class: 'print-warning',
        text: '当前为精简打印范围：仅包含前 ' + scope.rows.length + ' 条聚合发现（共 ' + groups.length +
          ' 条）。如需完整清单，请在页面上把打印范围切换为“完整打印”后重新打印。'
      })] : [printParagraph('本清单包含全部 ' + scope.rows.length + ' 条聚合发现。')]
    ).concat([
      printTable(['编号', '等级', '规则', '分类', '完整值', '来源数', '命中次数', '核查状态'], appendixRows, 'print-table-tight'),
      h('h3', { text: '6.2 资源与诊断' }),
      printTable(['项目', '内容'], [
        h('tr', null, [h('td', { text: '资源总数' }), h('td', { text: String((summary.resources || {}).total || 0) })]),
        h('tr', null, [h('td', { text: '诊断记录' }), h('td', { text: String((summary.issues || {}).total || 0) + ' 条' })]),
        h('tr', null, [h('td', { text: '参数名' }), h('td', { text: String(params.length) + ' 个：' + params.slice(0, 60).join(', ') + (params.length > 60 ? ' …' : '') })])
      ]),
      h('ul', { class: 'print-sources' }, (summary.resources && summary.resources.notes ? summary.resources.notes : []).map(function (note) {
        return h('li', { text: note });
      })),
      h('h3', { text: '6.3 报告附件' }),
      h('ul', { class: 'print-sources' }, [
        h('li', { text: 'report.html —— 交互式总览与工作台（本页）' }),
        h('li', { text: 'API报告.html / URL报告.html / 敏感信息报告.html / 参数报告.html / 路由报告.html / 资源报告.html / 主机资产报告.html' }),
        h('li', { text: 'api绝对路径.txt / api相对路径.txt / url.txt / 路由.txt / 参数.txt / 敏感信息.txt' }),
        h('li', { text: 'domain.txt / ip.txt / internal_hosts.txt —— 主机清单（标准化、去重后，每行一条）' }),
        h('li', { text: 'report.json —— 完整结构化结果' })
      ])
    ])));

    sections.forEach(function (node) { container.appendChild(node); });
  }

  function metricValue(key) {
    var metrics = summary.attackMetrics || [];
    for (var index = 0; index < metrics.length; index++) {
      if (metrics[index].key === key) return metrics[index].value;
    }
    return 0;
  }

  // ------------------------------------------------------------ CSV wiring

  function exportFindings() {
    var host = summary.targetHost || text(data.target);
    if (state.findingsView === 'group') {
      var rows = sortRows('findings', filterGroups(), groupSortValue);
      var csvText = csv.build(
        ['编号', '等级', '等级代码', '规则名称', '规则编号', '分类', '完整值', '来源数', '命中次数', '涉及域名', '核查状态', 'AI评级', '人工核查建议'],
        rows.map(function (group) {
          return [
            group.id, severityLabel(group.severity), group.severity, group.ruleName, group.ruleId,
            group.categoryLabel, group.value, (group.sources || []).length, group.hits,
            (group.domains || []).join(' '), group.confirmation || '待人工验证',
            group.ai ? group.ai.rating : '', group.verify
          ];
        })
      );
      download(csv.fileName('findings-grouped', host, rows.length), csvText);
      toast('已导出 ' + rows.length + ' 条聚合发现（当前筛选条件，非仅当前页）');
      return;
    }
    var hits = sortRows('findings', filterRawHits(), rawSortValue);
    var rawCSV = csv.build(
      ['编号', '等级', '等级代码', '规则名称', '规则编号', '分类', '完整值', '来源URL', '行', '列', 'AI评级', '核查状态'],
      hits.map(function (hit) {
        return [
          hit.id, severityLabel(hit.severity), hit.severity, hit.ruleName, hit.ruleId,
          hit.category === 'sensitive' ? '敏感信息' : hit.category === 'url' ? 'URL' : hit.category,
          hit.value, hit.url, hit.line, hit.column, hit.ai ? hit.ai.rating : '',
          hit.confirmation || '待人工验证'
        ];
      })
    );
    download(csv.fileName('findings-raw', host, hits.length), rawCSV);
    toast('已导出 ' + hits.length + ' 条原始命中（当前筛选条件，非仅当前页）');
  }

  function exportEndpoints() {
    var host = summary.targetHost || text(data.target);
    var rows = filterEndpoints();
    var csvText = csv.build(
      ['方法', '路径', '域名', '证据', '提取方式', '授权探测', '探测状态', '参数', '解析后URL', '源码原始写法', '来源URL', '行', '列', 'AI评估'],
      rows.map(function (endpoint) {
        var params = endpointParams(endpoint).map(function (row) { return row.origin + ':' + row.key; }).join(' ');
        var ai = endpoint.template && endpoint.template.ai;
        return [
          endpointMethod(endpoint), endpointPath(endpoint), endpointHost(endpoint),
          text(endpoint.evidence) || 'static',
          EXTRACTOR_LABELS[text(endpoint.source)] || text(endpoint.source),
          endpoint.authorized ? '是' : '否',
          endpoint.status_code || '未探测', params || '未提取',
          text(endpoint.url), text(endpoint.raw), text(endpoint.source_url),
          endpoint.line || '', endpoint.column || '',
          ai ? text(ai.completeness) : ''
        ];
      })
    );
    download(csv.fileName('endpoints', host, rows.length), csvText);
    toast('已导出 ' + rows.length + ' 个端点（当前筛选条件，非仅当前页）');
  }

  // --------------------------------------------------------------- tabs

  function activateTab(name) {
    state.tab = name;
    document.querySelectorAll('[data-tab]').forEach(function (button) {
      var active = button.getAttribute('data-tab') === name;
      button.classList.toggle('active', active);
      button.setAttribute('aria-selected', active ? 'true' : 'false');
    });
    document.querySelectorAll('.tab-panel').forEach(function (panel) {
      panel.hidden = panel.id !== 'panel-' + name;
    });
    if (name === 'endpoints') renderEndpoints();
    if (name === 'hosts') renderHosts();
    if (name === 'routes') renderRoutes();
    if (name === 'resources') renderResources();
    if (name === 'diagnostics') renderDiagnostics();
  }

  // --------------------------------------------------------------- init

  function fillSelect(id, values, labels) {
    var select = byId(id);
    if (!select) return;
    values.forEach(function (value) {
      select.appendChild(h('option', { value: value, text: labels ? labels(value) : value }));
    });
  }

  function init() {
    fillSelect('severity', severityRows.map(function (row) { return row.severity; }),
      function (value) { return severityLabel(value) + '（' + value + '）'; });
    fillSelect('category', Object.keys(categoryLabels), function (value) { return categoryLabels[value]; });
    fillSelect('rule', (summary.types || []).map(function (bucket) { return bucket.key; }));
    fillSelect('domain', findingDomains, function (value) { return value; });
    fillSelect('ep-domain', endpointDomains, function (value) { return value; });
    fillSelect('ep-method', endpointMethods, function (value) { return value; });
    fillSelect('host-kind', hostKinds, hostKindLabel);

    document.querySelectorAll('[data-tab]').forEach(function (button) {
      button.addEventListener('click', function () { activateTab(button.getAttribute('data-tab')); });
    });

    // Findings controls
    byId('severity').addEventListener('change', function (event) {
      state.severity = event.target.value; state.page = 1; renderFindings();
    });
    byId('category').addEventListener('change', function (event) {
      state.category = event.target.value; state.page = 1; renderFindings();
    });
    byId('rule').addEventListener('change', function (event) {
      state.rule = event.target.value; state.page = 1; renderFindings();
    });
    byId('domain').addEventListener('change', function (event) {
      state.domain = event.target.value; state.page = 1; renderFindings();
    });
    var searchTimer = null;
    byId('search').addEventListener('input', function (event) {
      clearTimeout(searchTimer);
      // Debounced: filtering must not rebuild the whole page per keystroke,
      // and charts are never re-rendered here.
      searchTimer = setTimeout(function () {
        state.search = event.target.value;
        state.page = 1;
        renderFindings();
      }, 200);
    });
    byId('findings-view').addEventListener('change', function (event) {
      state.findingsView = event.target.value;
      state.page = 1;
      // The column layout changes with the view, so the header (and the
      // sort direction it carries) is rebuilt and the sort reset.
      delete boundTables.findings;
      delete sortState.findings;
      renderFindings();
    });
    byId('page-size').addEventListener('change', function (event) {
      state.pageSize = parseInt(event.target.value, 10) || DEFAULT_PAGE_SIZE;
      state.page = 1;
      renderFindings();
    });
    byId('findings-export').addEventListener('click', exportFindings);
    byId('endpoints-export').addEventListener('click', exportEndpoints);
    byId('hosts-export').addEventListener('click', exportHosts);

    // Host controls
    byId('host-kind').addEventListener('change', function (event) {
      state.hostKind = event.target.value; state.hostPage = 1; renderHosts();
    });
    byId('host-group').addEventListener('change', function (event) {
      state.hostGroup = event.target.value; state.hostPage = 1; renderHosts();
    });
    var hostTimer = null;
    byId('host-search').addEventListener('input', function (event) {
      clearTimeout(hostTimer);
      hostTimer = setTimeout(function () {
        state.hostSearch = event.target.value;
        state.hostPage = 1;
        renderHosts();
      }, 200);
    });

    // Endpoint controls
    byId('ep-domain').addEventListener('change', function (event) {
      state.endpointDomain = event.target.value; state.endpointPage = 1; renderEndpoints();
    });
    byId('ep-method').addEventListener('change', function (event) {
      state.endpointMethod = event.target.value; state.endpointPage = 1; renderEndpoints();
    });
    var endpointTimer = null;
    byId('ep-search').addEventListener('input', function (event) {
      clearTimeout(endpointTimer);
      endpointTimer = setTimeout(function () {
        state.endpointSearch = event.target.value;
        state.endpointPage = 1;
        renderEndpoints();
      }, 200);
    });

    // Route/param controls
    var paramTimer = null;
    byId('param-search').addEventListener('input', function (event) {
      clearTimeout(paramTimer);
      paramTimer = setTimeout(function () { state.paramSearch = event.target.value; renderParams(); }, 150);
    });

    // Tree rail
    byId('toggle-tree').addEventListener('click', function () {
      var rail = byId('tree-rail');
      rail.classList.add('collapsed');
      byId('open-tree').hidden = false;
    });
    byId('open-tree').addEventListener('click', function () {
      byId('tree-rail').classList.remove('collapsed');
      byId('open-tree').hidden = true;
    });

    // Drawer
    byId('drawer-close').addEventListener('click', closeDrawer);
    document.addEventListener('keydown', function (event) {
      if (event.key === 'Escape' && drawerOpen()) closeDrawer();
    });

    // Print
    byId('print-scope').addEventListener('change', function (event) {
      state.printScope = event.target.value;
      buildPrintDoc();
    });
    byId('print-button').addEventListener('click', function () {
      buildPrintDoc();
      window.print();
    });

    state.printScope = groups.length > 500 ? 'summary' : 'full';
    byId('print-scope').value = state.printScope;
    buildPrintDoc();
    renderTree();
    renderOverview();
    renderFindings();
    renderHosts();
    renderParams();
    activateTab('overview');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
