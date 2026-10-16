// Shared by the overview and the standalone reports.
const reportCollator = new Intl.Collator('zh-CN', { numeric: true, sensitivity: 'base' });
function compareReportValues(a, b) {
  const ranks = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  if (Object.hasOwn(ranks, a) && Object.hasOwn(ranks, b)) return ranks[a] - ranks[b];
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  return reportCollator.compare(String(a == null ? '' : a), String(b == null ? '' : b));
}
function bindReportSort(table, onSort) {
  if (!table || !table.tHead) return;
  let active = -1, direction = 1;
  Array.from(table.tHead.rows[0].cells).forEach((header, column) => {
    const label = header.textContent;
    header.tabIndex = 0;
    header.style.cursor = 'pointer';
    header.title = '点击排序，再次点击切换升降序';
    header.setAttribute('aria-sort', 'none');
    const sort = () => {
      direction = active === column ? -direction : 1;
      active = column;
      Array.from(table.tHead.rows[0].cells).forEach((cell, index) => {
        cell.setAttribute('aria-sort', index === active ? (direction === 1 ? 'ascending' : 'descending') : 'none');
        cell.textContent = cell.dataset.sortLabel || cell.textContent;
        if (index === active) cell.textContent += direction === 1 ? ' ▲' : ' ▼';
      });
      onSort(column, direction);
    };
    header.dataset.sortLabel = label;
    header.addEventListener('click', sort);
    header.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); sort(); }
    });
  });
}
function reportCellValue(row, column) {
  const cell = row.cells[column];
  if (!cell) return '';
  if (cell.dataset.sortValue != null) return cell.dataset.sortValue;
  const code = cell.querySelector('code');
  if (code) return code.textContent.trim();
  const badge = cell.querySelector('.sev');
  if (badge) return badge.textContent.trim();
  return cell.textContent.replace(/复制|已复制/g, '').trim();
}
