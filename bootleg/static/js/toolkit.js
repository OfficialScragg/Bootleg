/* Bootleg -- toolkit page: tools tab, deploy tab, settings tab. */

(() => {
  const slug = window.TOOLKIT.slug;
  const api = (path) => `/api/toolkits/${slug}${path}`;

  /* ------------------------------------------------------------- rebuild */

  document.getElementById('rebuild')?.addEventListener('click', async (e) => {
    const button = e.currentTarget;
    const res = await Bootleg.post(api('/rebuild'), {}, button);
    const state = document.getElementById('build-state');
    state.className = 'badge ok';
    state.innerHTML = `<span class="dot ok"></span> rev ${res.stats.revision} · ${
      formatSize(res.stats.size)}`;
    Bootleg.toast(`Built revision ${res.stats.revision} — ${res.stats.tool_count} tools, ${
      formatSize(res.stats.size)} encrypted.`);
  });

  function formatSize(bytes) {
    const units = ['B', 'KB', 'MB', 'GB'];
    let n = Number(bytes) || 0, i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i += 1; }
    return `${i === 0 ? n.toFixed(0) : n.toFixed(1)} ${units[i]}`;
  }

  const markDirty = () => {
    const state = document.getElementById('build-state');
    if (state) {
      state.className = 'badge warn';
      state.innerHTML = '<span class="dot warn"></span> changes not built';
    }
  };

  /* --------------------------------------------------------- tools: upload */

  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('file-input');
  const progress = document.getElementById('upload-progress');

  if (dropzone) {
    dropzone.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', () => {
      if (fileInput.files.length) sendFiles(fileInput.files);
    });
    ['dragenter', 'dragover'].forEach((type) => dropzone.addEventListener(type, (e) => {
      e.preventDefault();
      dropzone.classList.add('over');
    }));
    ['dragleave', 'drop'].forEach((type) => dropzone.addEventListener(type, (e) => {
      e.preventDefault();
      if (type === 'dragleave' && dropzone.contains(e.relatedTarget)) return;
      dropzone.classList.remove('over');
    }));
    dropzone.addEventListener('drop', (e) => {
      if (e.dataTransfer.files.length) sendFiles(e.dataTransfer.files);
    });
  }

  async function sendFiles(files) {
    const list = Array.from(files);
    const form = new FormData();
    list.forEach((file) => form.append('file', file));

    const details = await askPlacement(list);
    if (!details) return;
    form.append('install_dir', details.install_dir);
    form.append('unpack', details.unpack ? '1' : '0');
    if (list.length === 1 && details.name) form.append('name', details.name);

    progress.hidden = false;
    const bar = progress.querySelector('i');
    try {
      await Bootleg.upload(api('/tools/upload'), form, (fraction) => {
        bar.style.width = `${Math.round(fraction * 100)}%`;
      });
      Bootleg.toast(`Archived ${list.length} file${list.length === 1 ? '' : 's'}.`);
      setTimeout(() => location.reload(), 450);
    } finally {
      progress.hidden = true;
      bar.style.width = '0';
      fileInput.value = '';
    }
  }

  /* Ask where files land before uploading -- cheaper than fixing it after. */
  function askPlacement(files) {
    const single = files.length === 1;
    const guessUnpack = files.some((f) => /\.(tar\.(gz|bz2|xz)|tgz|tbz2|txz|tar|zip)$/i.test(f.name));
    const total = files.reduce((sum, f) => sum + f.size, 0);
    return new Promise((resolve) => {
      let settled = false;
      const { close } = Bootleg.modal({
        title: single ? `Add ${files[0].name}` : `Add ${files.length} files`,
        body: `
          <p style="color:var(--muted);font-size:13px;margin-bottom:16px">
            ${formatSize(total)} total. These get packed into the encrypted archive.
          </p>
          ${single ? `
          <div class="field">
            <label class="lbl" for="up-name">Display name</label>
            <input type="text" id="up-name" value="${Bootleg.escapeHtml(files[0].name)}">
          </div>` : ''}
          <div class="field">
            <label class="lbl" for="up-dir">Folder inside the toolkit <span style="color:var(--faint);font-weight:400">optional</span></label>
            <input type="text" id="up-dir" placeholder="bin" spellcheck="false">
            <div class="hint">Leave blank to drop it at the toolkit root.</div>
          </div>
          <label class="check">
            <input type="checkbox" id="up-unpack" ${guessUnpack ? 'checked' : ''}>
            <span><b>Extract on the target host</b>
            Unpacks the archive after deployment and removes the tarball.</span>
          </label>`,
        confirm: 'Upload',
        onConfirm: (root) => {
          settled = true;
          resolve({
            name: root.querySelector('#up-name')?.value.trim() || '',
            install_dir: root.querySelector('#up-dir').value.trim(),
            unpack: root.querySelector('#up-unpack').checked,
          });
        },
      });
      const overlay = document.getElementById('overlay');
      const watch = new MutationObserver(() => {
        if (overlay.hidden && !settled) { settled = true; watch.disconnect(); resolve(null); }
      });
      watch.observe(overlay, { attributes: true, attributeFilter: ['hidden'] });
      void close;
    });
  }

  /* --------------------------------------------------------- tools: github */

  document.getElementById('add-github')?.addEventListener('click', () => {
    Bootleg.modal({
      title: 'Track a GitHub project',
      wide: true,
      body: `
        <div class="field">
          <label class="lbl" for="gh-repo">Repository</label>
          <input type="text" id="gh-repo" placeholder="owner/repo or a github.com URL" autofocus spellcheck="false">
        </div>
        <div class="seg" id="gh-source">
          <button type="button" class="active" data-source="release">Release asset</button>
          <button type="button" data-source="source">Source archive</button>
        </div>
        <div class="field" id="gh-pattern-field">
          <label class="lbl" for="gh-pattern">Asset filter <span style="color:var(--faint);font-weight:400">optional</span></label>
          <input type="text" id="gh-pattern" placeholder="*linux*amd64*" spellcheck="false">
          <div class="hint">A glob against the asset filename. Left blank, Bootleg picks the Linux x86-64 build.</div>
        </div>
        <div class="row">
          <div class="field" style="margin:0">
            <label class="lbl" for="gh-dir">Folder inside the toolkit</label>
            <input type="text" id="gh-dir" placeholder="bin" spellcheck="false">
          </div>
          <div class="field" style="margin:0">
            <label class="lbl" for="gh-name">Display name</label>
            <input type="text" id="gh-name" placeholder="defaults to the repo name">
          </div>
        </div>
        <div style="margin-top:14px;display:flex;flex-direction:column;gap:10px">
          <label class="check">
            <input type="checkbox" id="gh-unpack" checked>
            <span><b>Extract on the target host</b> Unpack the release archive after deploying.</span>
          </label>
          <label class="check">
            <input type="checkbox" id="gh-prerelease">
            <span><b>Include pre-releases</b> Track betas and release candidates too.</span>
          </label>
        </div>`,
      confirm: 'Track and fetch',
      onConfirm: async (root, button) => {
        const repo = root.querySelector('#gh-repo').value.trim();
        if (!repo) { Bootleg.toast('Enter a repository.', 'err'); return false; }
        button.textContent = 'Fetching release…';
        const res = await Bootleg.post(api('/tools/github'), {
          repo,
          source: root.querySelector('#gh-source .active').dataset.source,
          pattern: root.querySelector('#gh-pattern').value.trim(),
          install_dir: root.querySelector('#gh-dir').value.trim(),
          name: root.querySelector('#gh-name').value.trim(),
          unpack: root.querySelector('#gh-unpack').checked,
          prerelease: root.querySelector('#gh-prerelease').checked,
        });
        // A tracked repo can be added successfully but fail to resolve a build.
        const tool = res.tool;
        if (tool.version) Bootleg.toast(`Tracking ${repo} at ${tool.version}.`);
        else Bootleg.toast(`Tracking ${repo}, but nothing downloaded: ${tool.gh_status}`, 'warn', 8000);
        setTimeout(() => location.reload(), 500);
      },
    });

    const seg = document.getElementById('gh-source');
    seg.addEventListener('click', (e) => {
      const button = e.target.closest('button');
      if (!button) return;
      seg.querySelectorAll('button').forEach((b) => b.classList.toggle('active', b === button));
      document.getElementById('gh-pattern-field').style.display =
        button.dataset.source === 'source' ? 'none' : '';
    });
  });

  /* ---------------------------------------------------------- tool rows */

  document.getElementById('tool-rows')?.addEventListener('click', async (e) => {
    const button = e.target.closest('button');
    if (!button) return;
    const row = button.closest('tr');
    const id = row.dataset.id;
    const name = row.querySelector('.tool-name').textContent.trim();

    if (button.classList.contains('js-refresh')) {
      const res = await Bootleg.post(`/api/tools/${id}/refresh`, {}, button);
      row.querySelector('.js-status').textContent = res.result.message;
      row.querySelector('.js-version').textContent = res.tool.version || '—';
      if (res.result.updated) {
        row.querySelector('.js-version').className = 'badge accent js-version';
        markDirty();
        Bootleg.toast(`${name}: ${res.result.message}`);
      } else {
        Bootleg.toast(`${name}: ${res.result.message}`, 'warn');
      }
      return;
    }

    if (button.classList.contains('js-delete')) {
      Bootleg.confirmDialog('Remove tool',
        `Remove <b>${Bootleg.escapeHtml(name)}</b> from this toolkit? The archived copy is deleted.`,
        async () => {
          await Bootleg.post(`/api/tools/${id}/delete`);
          row.remove();
          markDirty();
          Bootleg.toast(`Removed ${name}.`);
          const count = document.getElementById('tool-count');
          count.textContent = document.querySelectorAll('#tool-rows tr').length;
        }, 'Remove');
      return;
    }

    if (button.classList.contains('js-edit')) editTool(row, id);
  });

  function editTool(row, id) {
    const path = row.querySelector('.tool-path').textContent.trim();
    const dir = path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '';
    const enabled = !row.classList.contains('disabled');
    const unpacks = !!row.querySelector('.badge[title]');
    Bootleg.modal({
      title: 'Edit placement',
      body: `
        <div class="field">
          <label class="lbl" for="ed-name">Display name</label>
          <input type="text" id="ed-name" value="${Bootleg.escapeHtml(
            row.querySelector('.tool-name').textContent.trim())}">
        </div>
        <div class="field">
          <label class="lbl" for="ed-dir">Folder inside the toolkit</label>
          <input type="text" id="ed-dir" value="${Bootleg.escapeHtml(dir)}" placeholder="bin" spellcheck="false">
        </div>
        <div style="display:flex;flex-direction:column;gap:10px">
          <label class="check">
            <input type="checkbox" id="ed-unpack" ${unpacks ? 'checked' : ''}>
            <span><b>Extract on the target host</b></span>
          </label>
          <label class="check">
            <input type="checkbox" id="ed-enabled" ${enabled ? 'checked' : ''}>
            <span><b>Include in the archive</b> Uncheck to keep it here but leave it out of deploys.</span>
          </label>
        </div>`,
      confirm: 'Save',
      onConfirm: async (root) => {
        await Bootleg.post(`/api/tools/${id}`, {
          name: root.querySelector('#ed-name').value.trim(),
          install_dir: root.querySelector('#ed-dir').value.trim(),
          unpack: root.querySelector('#ed-unpack').checked,
          enabled: root.querySelector('#ed-enabled').checked,
        });
        markDirty();
        location.reload();
      },
    });
  }

  document.getElementById('check-updates')?.addEventListener('click', async (e) => {
    const button = e.currentTarget;
    button.innerHTML = 'Checking…';
    const res = await Bootleg.post(api('/refresh'), {}, button);
    const { checked, updated } = res.result;
    if (updated) {
      Bootleg.toast(`${updated} of ${checked} updated — archive rebuilt.`);
      setTimeout(() => location.reload(), 700);
    } else {
      Bootleg.toast(`Checked ${checked} project${checked === 1 ? '' : 's'}: all up to date.`);
      setTimeout(() => location.reload(), 700);
    }
  });

  /* ------------------------------------------------------------- deploy */

  /* Minimal Python highlighter. Hand-rolled on purpose: Bootleg pulls nothing
     from a CDN, so it still works on an air-gapped server. */
  const PY_KEYWORDS = new Set(['False', 'None', 'True', 'and', 'as', 'assert', 'async',
    'await', 'break', 'class', 'continue', 'def', 'del', 'elif', 'else', 'except',
    'finally', 'for', 'from', 'global', 'if', 'import', 'in', 'is', 'lambda', 'nonlocal',
    'not', 'or', 'pass', 'raise', 'return', 'try', 'while', 'with', 'yield']);
  const PY_BUILTINS = new Set(['abs', 'bool', 'bytes', 'dict', 'enumerate', 'float', 'int',
    'isinstance', 'len', 'list', 'max', 'min', 'open', 'print', 'range', 'repr', 'reversed',
    'set', 'sorted', 'str', 'sum', 'super', 'tuple', 'type', 'zip', 'self', 'Exception',
    'ValueError', 'OSError', 'TypeError']);

  const PY_TOKEN = new RegExp([
    '"""[\\s\\S]*?"""',                    // triple-quoted strings
    "'''[\\s\\S]*?'''",
    '[rbfu]{0,2}"(?:[^"\\\\\\n]|\\\\.)*"',  // single-line strings
    "[rbfu]{0,2}'(?:[^'\\\\\\n]|\\\\.)*'",
    '#[^\\n]*',                            // comments
    '@[A-Za-z_][\\w.]*',                   // decorators
    '\\b\\d[\\w.]*',                       // numbers
    '\\b[A-Za-z_]\\w*',                    // identifiers
  ].join('|'), 'g');

  function highlightPython(src) {
    const esc = Bootleg.escapeHtml;
    let out = '', last = 0, match, declaring = false;
    PY_TOKEN.lastIndex = 0;
    while ((match = PY_TOKEN.exec(src)) !== null) {
      out += esc(src.slice(last, match.index));
      const text = match[0];
      let cls = null;
      if (text.startsWith('#')) cls = 'c';
      else if (/^[rbfu]{0,2}["']/.test(text)) cls = 's';
      else if (text.startsWith('@')) cls = 'd';
      else if (/^\d/.test(text)) cls = 'n';
      else if (declaring) { cls = 'f'; declaring = false; }
      else if (PY_KEYWORDS.has(text)) { cls = 'k'; declaring = (text === 'def' || text === 'class'); }
      else if (PY_BUILTINS.has(text)) cls = 'b';
      out += cls ? '<span class="t-' + cls + '">' + esc(text) + '</span>' : esc(text);
      last = match.index + text.length;
    }
    return out + esc(src.slice(last));
  }

  if (window.TOOLKIT.tab === 'deploy') {
    const preview = document.getElementById('script-preview');
    Bootleg.get(api('/script'))
      .then((res) => { preview.innerHTML = highlightPython(res.script); })
      .catch(() => { preview.textContent = 'Could not load the agent source.'; });

    const issuedBox = document.getElementById('issued-box');
    const issuedKey = document.getElementById('issued-key');
    const issuedHint = document.getElementById('issued-hint');

    /* Every copy mints its own key -- that is what makes them single use. */
    async function issueKey(label, button) {
      const res = await Bootleg.post(api('/issue-key'), { label }, button);
      issuedKey.textContent = res.key;
      issuedBox.hidden = false;
      issuedHint.hidden = false;
      issuedBox.classList.add('masked');
      renderKeys(res.keys);
      return res;
    }

    document.getElementById('issued-toggle').addEventListener('click', () => {
      issuedBox.classList.toggle('masked');
    });

    document.getElementById('copy-script').addEventListener('click', async (e) => {
      const res = await issueKey('copied script', e.currentTarget);
      Bootleg.copy(res.script, 'Script copied with key #' + res.id + ' — locks to the first host that uses it.');
    });

    document.getElementById('copy-oneliner').addEventListener('click', async (e) => {
      const res = await issueKey('copied one-liner', e.currentTarget);
      // base64 keeps quotes, newlines and the key intact through any shell.
      const encoded = btoa(String.fromCharCode(...new TextEncoder().encode(res.script)));
      const command = 'echo ' + encoded + ' | base64 -d > bootleg_deploy.py && python3 bootleg_deploy.py';
      Bootleg.copy(command, 'Command copied with key #' + res.id + ' — locks to the first host that uses it.');
    });

    document.getElementById('change-url').addEventListener('click', () => {
      const current = document.getElementById('server-url').textContent.trim();
      Bootleg.modal({
        title: 'Server address',
        body: '<div class="field">'
          + '<label class="lbl" for="su-url">Where agents should call home</label>'
          + '<input type="text" id="su-url" value="' + Bootleg.escapeHtml(current) + '" spellcheck="false">'
          + '<div class="hint">Use an address your targets can actually reach, not localhost. '
          + 'This is baked into every key issued from now on; keys already handed out keep the old address.</div>'
          + '</div>',
        confirm: 'Save address',
        onConfirm: async (root) => {
          const url = root.querySelector('#su-url').value.trim();
          if (!/^https?:\/\/\S+$/.test(url)) {
            Bootleg.toast('Start the URL with http:// or https://', 'err');
            return false;
          }
          const res = await Bootleg.post('/api/settings', { public_url: url });
          document.getElementById('server-url').textContent = res.public_url;
          Bootleg.toast('Server address updated.');
        },
      });
    });

    function renderKeys(keys) {
      const body = document.getElementById('key-rows');
      const empty = document.getElementById('keys-empty');
      const esc = Bootleg.escapeHtml;
      body.innerHTML = keys.map((k) => {
        let status, actions = '';
        if (k.revoked) {
          status = '<span class="badge danger">revoked</span>';
        } else if (k.bound_ip) {
          status = '<span class="badge accent" title="First deployed ' + esc(k.used_at || '') + '">'
            + esc(k.bound_ip) + '</span>'
            + '<span style="color:var(--faint);font-size:11.5px"> · ' + k.use_count
            + ' deploy' + (k.use_count === 1 ? '' : 's') + '</span>';
          actions = '<button class="btn ghost sm js-unbind" title="Release the host lock so this script works from a new address">Unlock</button>';
        } else {
          status = '<span class="badge ok"><span class="dot ok"></span> not yet used</span>';
        }
        if (!k.revoked) {
          actions += '<button class="btn ghost sm js-revoke" title="Revoke this key">Revoke</button>';
        }
        const label = k.label ? ' <span style="color:var(--faint)">' + esc(k.label) + '</span>' : '';
        return '<tr data-id="' + k.id + '"><td class="mono">#' + k.id + label + '</td>'
          + '<td class="mono" style="color:var(--muted)">' + esc(k.created_at.slice(0, 16).replace('T', ' ')) + '</td>'
          + '<td>' + status + '</td><td class="actions">' + actions + '</td></tr>';
      }).join('');
      empty.hidden = keys.length > 0;
      document.getElementById('key-count').textContent =
        keys.filter((k) => k.state === 'ready').length + ' unused';
    }

    document.getElementById('key-rows').addEventListener('click', async (e) => {
      const button = e.target.closest('.js-revoke, .js-unbind');
      if (!button) return;
      const id = button.closest('tr').dataset.id;
      const unbinding = button.classList.contains('js-unbind');
      await Bootleg.post('/api/keys/' + id + '/' + (unbinding ? 'unbind' : 'revoke'), {}, button);
      renderKeys((await Bootleg.get(api('/keys'))).keys);
      Bootleg.toast(unbinding ? 'Key #' + id + ' unlocked — it can bind to a new host.'
                              : 'Key #' + id + ' revoked.');
    });

    document.getElementById('prune-keys').addEventListener('click', async (e) => {
      const res = await Bootleg.post(api('/keys/prune'), {}, e.currentTarget);
      renderKeys(res.keys);
      Bootleg.toast(res.removed ? 'Removed ' + res.removed + ' key' + (res.removed === 1 ? '' : 's') + '.'
                                : 'Nothing to tidy.');
    });
  }


  /* ----------------------------------------------------------- settings */

  document.getElementById('save-details')?.addEventListener('click', async (e) => {
    await Bootleg.post(api(''), {
      name: document.getElementById('tk-name').value.trim(),
      description: document.getElementById('tk-desc').value.trim(),
    }, e.currentTarget);
    Bootleg.toast('Saved.');
  });

  document.getElementById('save-setup')?.addEventListener('click', async (e) => {
    await Bootleg.post(api(''), {
      setup_script: document.getElementById('setup-script').value,
    }, e.currentTarget);
    markDirty();
    Bootleg.toast('Setup script saved — rebuild to ship it.');
  });

  document.getElementById('rotate-key')?.addEventListener('click', () => {
    Bootleg.confirmDialog('Re-key this toolkit',
      'Every unused deploy key is revoked and the archive is re-encrypted under a new secret. Scripts already handed out stop working. Continue?',
      async () => {
        await Bootleg.post(api('/rotate'));
        Bootleg.toast('Toolkit re-keyed. Outstanding keys revoked — issue a new script.');
        setTimeout(() => { location.href = `/toolkit/${slug}/deploy`; }, 800);
      }, 'Rotate key');
  });

  document.getElementById('delete-toolkit')?.addEventListener('click', () => {
    Bootleg.confirmDialog('Delete toolkit',
      `Delete <b>${Bootleg.escapeHtml(window.TOOLKIT.name)}</b> and every file archived in it? This cannot be undone.`,
      async () => {
        await Bootleg.post(api('/delete'));
        location.href = '/';
      }, 'Delete forever');
  });
})();
