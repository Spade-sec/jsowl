// Dependency-free chart builders for the overview dashboard.
//
// Two rules drive this module:
//   1. Numbers come from the Go summary, never from a second computation in
//      the browser, so a chart and its table always agree.
//   2. Everything a user can click is a real focusable control with an
//      accessible name, so charts stay usable without a mouse.
// No innerHTML and no string-concatenated markup: every label is written with
// textContent, which keeps target-controlled text (rule names, values, hosts)
// inert.
(function (global) {
  'use strict';

  var SVG_NS = 'http://www.w3.org/2000/svg';

  var COLORS = {
    critical: '#a3291f',
    high: '#d64545',
    medium: '#d68910',
    low: '#2f6fed',
    info: '#8a919c',
    unknown: '#6b7280'
  };

  function colorFor(severity) {
    return COLORS[severity] || COLORS.unknown;
  }

  function truncate(text, limit) {
    var value = String(text == null ? '' : text);
    var chars = Array.from(value);
    if (chars.length <= limit) return value;
    return chars.slice(0, limit).join('') + '…';
  }

  function element(name, attrs) {
    var node = document.createElement(name);
    setAttrs(node, attrs);
    return node;
  }

  function svgElement(name, attrs) {
    var node = document.createElementNS(SVG_NS, name);
    setAttrs(node, attrs);
    return node;
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

  // makeInteractive turns any element into a keyboard-operable button-shaped
  // control: focusable, named, and activated by click, Enter or Space.
  function makeInteractive(node, label, activate) {
    node.setAttribute('role', 'button');
    node.setAttribute('tabindex', '0');
    node.setAttribute('aria-label', label);
    node.classList.add('chart-hit');
    node.addEventListener('click', function (event) {
      event.preventDefault();
      activate();
    });
    node.addEventListener('keydown', function (event) {
      if (event.key === 'Enter' || event.key === ' ' || event.key === 'Spacebar') {
        event.preventDefault();
        activate();
      }
    });
    return node;
  }

  function emptyState(container, message) {
    container.textContent = '';
    var note = element('p', { class: 'chart-empty', text: message });
    container.appendChild(note);
  }

  // donut draws a ring of proportional slices. A single slice renders as a
  // complete ring (no degenerate arc), and a total of zero renders an
  // explicit empty state instead of a blank circle.
  function donut(container, items, options) {
    var opts = options || {};
    container.textContent = '';
    var rows = (items || []).filter(function (item) { return item.count > 0; });
    var total = rows.reduce(function (sum, item) { return sum + item.count; }, 0);
    if (total === 0) {
      emptyState(container, opts.emptyText || '本项无数据');
      return;
    }

    var size = 190, radius = 70, thickness = 26;
    var center = size / 2;
    var circumference = 2 * Math.PI * radius;
    var svg = svgElement('svg', {
      viewBox: '0 0 ' + size + ' ' + size,
      width: size, height: size,
      class: 'chart-donut',
      role: 'group',
      'aria-label': (opts.title || '分布图') + '，共 ' + total + (opts.unit || '')
    });

    svg.appendChild(svgElement('circle', {
      cx: center, cy: center, r: radius, fill: 'none',
      stroke: '#eef0f4', 'stroke-width': thickness
    }));

    var gap = rows.length > 1 ? 2 : 0;
    var offset = 0;
    rows.forEach(function (row) {
      var length = circumference * (row.count / total);
      var arc = svgElement('circle', {
        cx: center, cy: center, r: radius, fill: 'none',
        stroke: colorFor(row.severity),
        'stroke-width': thickness,
        'stroke-dasharray': Math.max(length - gap, 0.5) + ' ' + (circumference - Math.max(length - gap, 0.5)),
        'stroke-dashoffset': -offset,
        transform: 'rotate(-90 ' + center + ' ' + center + ')'
      });
      offset += length;
      var label = (row.label || row.key) + ' ' + row.count + (opts.unit || '') +
        '，占比 ' + Math.round((row.count / total) * 100) + '%' +
        (opts.actionLabel ? '，' + opts.actionLabel : '');
      makeInteractive(arc, label, function () {
        if (opts.onSelect) opts.onSelect(row.key, row);
      });
      svg.appendChild(arc);
    });

    var value = svgElement('text', {
      x: center, y: center - 2, 'text-anchor': 'middle',
      class: 'donut-total', text: String(total)
    });
    var caption = svgElement('text', {
      x: center, y: center + 18, 'text-anchor': 'middle',
      class: 'donut-label', text: opts.centerLabel || '合计'
    });
    svg.appendChild(value);
    svg.appendChild(caption);
    container.appendChild(svg);

    var legend = element('ul', { class: 'chart-legend' });
    rows.forEach(function (row) {
      var item = element('li');
      var button = element('button', {
        type: 'button',
        class: 'legend-item',
        'aria-label': (row.label || row.key) + ' ' + row.count + (opts.unit || '') + '，点击筛选'
      });
      button.appendChild(element('span', {
        class: 'legend-swatch', style: 'background:' + colorFor(row.severity)
      }));
      button.appendChild(element('span', { class: 'legend-label', text: row.label || row.key }));
      button.appendChild(element('span', { class: 'legend-value', text: String(row.count) }));
      button.addEventListener('click', function () {
        if (opts.onSelect) opts.onSelect(row.key, row);
      });
      item.appendChild(button);
      legend.appendChild(item);
    });
    container.appendChild(legend);
  }

  // barList draws a ranked list of labelled bars. Each row is a real button,
  // so the ranking is fully keyboard navigable.
  function barList(container, items, options) {
    var opts = options || {};
    container.textContent = '';
    var rows = (items || []).filter(function (item) { return item.count > 0; });
    if (rows.length === 0) {
      emptyState(container, opts.emptyText || '本项无数据');
      return;
    }
    var max = rows.reduce(function (peak, item) { return Math.max(peak, item.count); }, 0);
    var list = element('ul', { class: 'bar-list' });
    rows.forEach(function (row) {
      var item = element('li');
      var label = row.label || row.key;
      var button = element('button', {
        type: 'button',
        class: 'bar-row',
        'aria-label': label + ' ' + row.count + (opts.unit || '') +
          (opts.actionLabel ? '，' + opts.actionLabel : '')
      });
      button.appendChild(element('span', {
        class: 'bar-label', text: truncate(label, opts.labelLimit || 28), title: label
      }));
      var track = element('span', { class: 'bar-track' });
      track.appendChild(element('span', {
        class: 'bar-fill',
        style: 'width:' + Math.max(2, Math.round((row.count / max) * 100)) + '%;background:' +
          colorFor(row.severity)
      }));
      button.appendChild(track);
      button.appendChild(element('span', { class: 'bar-value', text: String(row.count) }));
      button.addEventListener('click', function () {
        if (opts.onSelect) opts.onSelect(row.key, row);
      });
      item.appendChild(button);
      list.appendChild(item);
    });
    container.appendChild(list);
  }

  global.JsOwlCharts = {
    donut: donut,
    barList: barList,
    colorFor: colorFor,
    truncate: truncate,
    element: element
  };
})(window);
