// Live departure board: polls the public catalog and flips only the rows that changed.
// Pauses while the tab is hidden, backs off on errors, and keeps the last good board on screen.
(() => {
  'use strict';
  const board = document.querySelector('[data-board-live]');
  if (!board) return;
  const list = board.querySelector('.board-list');
  const limit = Number(board.dataset.limit) || 0;
  const every = Math.max(15, Number(board.dataset.refresh) || 30) * 1000;
  const note = board.querySelector('[data-board-note]');
  const noteText = note?.textContent || '';
  const TIMEOUT_MS = 10000;
  let timer = 0;
  let failures = 0;
  let lastRun = Date.now();
  let inFlight = false;
  let latest = 0;

  const el = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };

  function row(model) {
    const item = el('li', 'board-row');
    item.dataset.model = model.id;
    const roundel = el('span', 'roundel');
    roundel.dataset.line = model.line?.family || 'other';
    roundel.setAttribute('aria-hidden', 'true');
    roundel.append(el('b', '', model.line?.letter || '?'), el('i', '', model.line?.number || '00'));
    const name = el('div', 'model', model.id);
    name.append(el('small', '', model.name !== model.id ? model.name : model.category));
    const protocols = model.verification?.protocols?.length || 0;
    const use = el('div', 'use', model.category);
    use.append(el('small', '', protocols ? `已实测 ${protocols} 种协议` : model.text_candidate ? '可计费 · 待本站实测' : '—'));
    item.append(roundel, name, use, el('span', `lamp ${model.state?.tone || 'off'}`, model.state?.label || '—'));
    return item;
  }

  // Server-rendered and script-built rows differ only in whitespace; compare what a rider sees.
  const look = item => [
    item.textContent.replace(/\s+/g, ''),
    item.querySelector('.lamp')?.className,
    item.querySelector('.roundel')?.dataset.line,
  ].join('|');

  function render(data) {
    const models = (Array.isArray(data.models) ? data.models : []).slice(0, limit || undefined);
    const current = new Map([...list.children].map(item => [item.dataset.model, item]));
    const next = models.map(model => {
      const fresh = row(model);
      const old = current.get(model.id);
      return old && look(old) === look(fresh) ? old : fresh; // a new node plays the flap animation
    });
    [...list.children].forEach(item => { if (!next.includes(item)) item.remove(); });
    next.forEach((item, index) => { if (list.children[index] !== item) list.insertBefore(item, list.children[index] || null); });

    board.querySelector('.board-empty')?.toggleAttribute('hidden', models.length > 0);
    const count = board.querySelector('[data-board-count]');
    if (count) count.textContent = data.model_count ?? models.length;
    board.querySelector('[data-board-more]')?.toggleAttribute('hidden', !data.model_count);
    const clock = board.querySelector('[data-board-clock]');
    const stamp = new Date(data.updated_at);
    if (clock && !Number.isNaN(stamp.getTime())) {
      clock.setAttribute('datetime', data.updated_at);
      clock.textContent = stamp.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
    }
    const status = document.querySelector('[data-line-status]');
    if (status) status.textContent = data.status === 'operational' ? '全线正常运行' : '部分线路异常';
    const billable = document.querySelector('[data-line-billable]');
    if (billable && Number.isFinite(data.billable_count)) billable.textContent = data.billable_count;
  }

  function nightService() {
    const hour = new Date().getHours();
    const sub = board.querySelector('[data-board-sub]');
    if (sub) sub.textContent = hour >= 23 || hour < 5 ? 'NIGHT SERVICE · 夜行线运行中' : 'DEPARTURES · MODEL LINES';
  }

  function flash(text, className) {
    if (!note) return;
    note.textContent = text;
    board.classList.remove('is-fresh', 'is-stale');
    if (className) board.classList.add(className);
  }

  // One request at a time; each carries a generation so a late answer can never overwrite a newer one.
  async function refresh() {
    if (inFlight) return;
    const generation = ++latest;
    const controller = new AbortController();
    const deadline = setTimeout(() => controller.abort(), TIMEOUT_MS);
    inFlight = true;
    lastRun = Date.now();
    try {
      const response = await fetch(board.dataset.boardLive, { cache: 'no-store', credentials: 'same-origin', headers: { Accept: 'application/json' }, signal: controller.signal });
      if (!response.ok) throw new Error(String(response.status));
      const data = await response.json(); // the deadline also covers reading the body
      if (generation !== latest) return;
      render(data);
      failures = 0;
      flash('刚刚更新', 'is-fresh');
      setTimeout(() => { if (!failures) flash(noteText, ''); }, 2400);
    } catch {
      if (generation !== latest) return;
      failures += 1;
      flash('暂时无法刷新', 'is-stale');
    } finally {
      clearTimeout(deadline);
      inFlight = false;
      nightService();
      schedule();
    }
  }

  function schedule() {
    clearTimeout(timer);
    if (inFlight || document.visibilityState !== 'visible') return;
    const delay = every * Math.min(2 ** failures, 8);
    timer = setTimeout(refresh, Math.max(0, delay - (Date.now() - lastRun)));
  }

  document.addEventListener('visibilitychange', schedule);
  nightService();
  schedule();
})();
