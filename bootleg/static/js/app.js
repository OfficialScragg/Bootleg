/* Bootleg -- shared UI helpers: fetch wrapper, toasts, modals, clipboard. */

const Bootleg = (() => {
  const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || '';

  function toast(message, kind = 'ok', ms = 4200) {
    const el = document.createElement('div');
    el.className = 'toast' + (kind === 'ok' ? '' : ' ' + kind);
    el.innerHTML = `<svg width="15" height="15" style="flex:0 0 auto;margin-top:1px;color:var(--${
      kind === 'err' ? 'danger' : kind === 'warn' ? 'warn' : 'accent'})"><use href="#i-${
      kind === 'ok' ? 'check' : 'alert'}"/></svg><div></div>`;
    el.lastChild.textContent = message;
    document.getElementById('toasts').appendChild(el);
    setTimeout(() => el.remove(), ms);
    return el;
  }

  async function request(url, options = {}, button = null) {
    const previous = button ? button.innerHTML : null;
    if (button) { button.disabled = true; button.style.opacity = '0.6'; }
    try {
      const res = await fetch(url, {
        ...options,
        headers: { 'X-CSRF-Token': csrf(), ...(options.headers || {}) },
      });
      let data = {};
      try { data = await res.json(); } catch (_) { /* empty or non-JSON body */ }
      if (!res.ok) throw new Error(data.error || `Request failed (HTTP ${res.status})`);
      return data;
    } catch (err) {
      toast(err.message || 'Something went wrong.', 'err', 6000);
      throw err;
    } finally {
      if (button) { button.disabled = false; button.style.opacity = ''; if (previous) button.innerHTML = previous; }
    }
  }

  const post = (url, body, button) => request(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  }, button);

  const get = (url) => request(url);

  /* Upload with real progress -- fetch cannot report it, so XHR it is. */
  function upload(url, formData, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', url);
      xhr.setRequestHeader('X-CSRF-Token', csrf());
      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable && onProgress) onProgress(e.loaded / e.total);
      });
      xhr.addEventListener('load', () => {
        let data = {};
        try { data = JSON.parse(xhr.responseText); } catch (_) { /* ignore */ }
        if (xhr.status >= 200 && xhr.status < 300) return resolve(data);
        const message = data.error || `Upload failed (HTTP ${xhr.status})`;
        toast(message, 'err', 6000);
        reject(new Error(message));
      });
      xhr.addEventListener('error', () => {
        toast('Upload failed — the connection dropped.', 'err');
        reject(new Error('network'));
      });
      xhr.send(formData);
    });
  }

  async function copy(text, label = 'Copied to clipboard') {
    try {
      await navigator.clipboard.writeText(text);
    } catch (_) {
      // Clipboard API needs a secure context; fall back for plain-http hosting.
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch (e) {
        toast('Could not copy — select the text and copy manually.', 'err');
        ta.remove();
        return false;
      }
      ta.remove();
    }
    toast(label);
    return true;
  }

  /* Modal. onConfirm may return false to keep the dialog open. */
  function modal({ title, body, confirm = 'Confirm', danger = false, wide = false, onConfirm }) {
    const overlay = document.getElementById('overlay');
    overlay.innerHTML = `
      <div class="modal${wide ? ' wide' : ''}" role="dialog" aria-modal="true">
        <div class="modal-head"><h2></h2></div>
        <div class="modal-body"></div>
        <div class="modal-foot">
          <button class="btn" data-close>Cancel</button>
          <button class="btn ${danger ? 'danger' : 'primary'}" data-confirm></button>
        </div>
      </div>`;
    overlay.querySelector('h2').textContent = title;
    overlay.querySelector('.modal-body').innerHTML = body;
    const confirmBtn = overlay.querySelector('[data-confirm]');
    confirmBtn.textContent = confirm;
    overlay.hidden = false;

    const close = () => {
      overlay.hidden = true;
      overlay.innerHTML = '';
      document.removeEventListener('keydown', onKey);
    };
    const onKey = (e) => {
      if (e.key === 'Escape') close();
      if (e.key === 'Enter' && e.target.tagName !== 'TEXTAREA') confirmBtn.click();
    };
    document.addEventListener('keydown', onKey);
    overlay.querySelector('[data-close]').addEventListener('click', close);
    overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
    confirmBtn.addEventListener('click', async () => {
      try {
        const result = await onConfirm(overlay, confirmBtn);
        if (result !== false) close();
      } catch (_) { /* the request already reported itself */ }
    });
    overlay.querySelector('input, textarea, select')?.focus();
    return { close, root: overlay };
  }

  function confirmDialog(title, message, action, confirmLabel = 'Delete') {
    return modal({
      title,
      body: `<p style="color:var(--muted);margin:0">${message}</p>`,
      confirm: confirmLabel,
      danger: true,
      onConfirm: action,
    });
  }

  const escapeHtml = (text) => String(text ?? '').replace(/[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  return { toast, post, get, request, upload, copy, modal, confirmDialog, escapeHtml };
})();
