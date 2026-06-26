const { invoke } = window.__TAURI__.core;
const tauriEvent = window.__TAURI__.event;

// ----------------------- estado da UI -----------------------
let current = null; // último VaultInfo recebido
let fileFilter = "";

// ----------------------- utilidades -----------------------
function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  const u = ["KB", "MB", "GB", "TB"];
  let i = -1;
  do {
    n /= 1024;
    i++;
  } while (n >= 1024 && i < u.length - 1);
  return `${n.toFixed(1)} ${u[i]}`;
}

function fmtPct(x) {
  return `${(x * 100).toFixed(1)}%`;
}

function fmtDate(secs) {
  if (!secs) return "—";
  return new Date(secs * 1000).toLocaleString("pt-BR");
}

function $(id) {
  return document.getElementById(id);
}

let toastTimer = null;
function toast(msg, isError = false, sticky = false) {
  const el = $("toast");
  el.textContent = msg;
  el.classList.toggle("error", isError);
  el.classList.remove("hidden");
  clearTimeout(toastTimer);
  if (!sticky) {
    toastTimer = setTimeout(() => el.classList.add("hidden"), 3200);
  }
}

async function call(cmd, args = {}) {
  return await invoke(cmd, args);
}

// ----------------------- renderização -----------------------
function showWelcome() {
  current = null;
  $("welcome").classList.remove("hidden");
  $("workspace").classList.add("hidden");
  $("mounted").classList.add("hidden");
  $("vaultPath").classList.add("hidden");
}

function showMounted(mountpoint) {
  current = null;
  $("welcome").classList.add("hidden");
  $("workspace").classList.add("hidden");
  $("mounted").classList.remove("hidden");
  $("mountAt").textContent = mountpoint;
}

function render(info) {
  current = info;
  $("welcome").classList.add("hidden");
  $("workspace").classList.remove("hidden");

  const pathEl = $("vaultPath");
  pathEl.textContent = info.path;
  pathEl.classList.remove("hidden");

  renderStats(info.stats);
  renderFiles(info.files);
  renderSnapshots(info.snapshots);
}

function renderStats(s) {
  const lock = s.encrypted ? "🔒 cifrado" : "🔓 aberto";
  const badges = [
    ["Arquivos", s.files],
    ["Blocos únicos", s.unique_blocks],
    ["Snapshots", s.snapshots],
    ["Lógico", fmtBytes(s.logical_bytes)],
    ["Em disco", fmtBytes(s.physical_bytes)],
    ["Dedup", fmtPct(s.dedup_savings)],
    ["Compressão", fmtPct(s.compression_savings)],
    ["Economia total", fmtPct(s.total_savings)],
  ];
  $("stats").innerHTML =
    `<div class="badge state">${lock}</div>` +
    badges
      .map(
        ([k, v]) =>
          `<div class="badge"><span class="k">${k}</span><span class="v">${v}</span></div>`
      )
      .join("");
}

function renderFiles(files) {
  const tbody = $("fileList");
  const f = fileFilter.trim().toLowerCase();
  const rows = files.filter((x) => !f || x.path.toLowerCase().includes(f));
  if (rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">nenhum arquivo</td></tr>`;
    return;
  }
  tbody.innerHTML = rows
    .map(
      (x) => `
      <tr>
        <td class="path">${escapeHtml(x.path)}</td>
        <td class="num">${fmtBytes(x.size)}</td>
        <td class="num dim">${fmtDate(x.mtime)}</td>
        <td class="row-actions">
          <button class="small" data-act="extract" data-path="${escapeAttr(x.path)}">⬇️</button>
          <button class="small danger" data-act="remove" data-path="${escapeAttr(x.path)}">🗑️</button>
        </td>
      </tr>`
    )
    .join("");
}

function renderSnapshots(snaps) {
  const ul = $("snapList");
  if (snaps.length === 0) {
    ul.innerHTML = `<li class="empty">nenhum snapshot</li>`;
    return;
  }
  ul.innerHTML = snaps
    .map(
      (s) => `
      <li>
        <div class="snap-info">
          <span class="snap-name">${escapeHtml(s.name)}</span>
          <span class="snap-meta">${s.files} arq · ${fmtBytes(s.size)} · ${fmtDate(s.created)}</span>
        </div>
        <div class="snap-actions">
          <button class="small" data-snap-act="restore" data-name="${escapeAttr(s.name)}">↩️ Restaurar</button>
          <button class="small danger" data-snap-act="delete" data-name="${escapeAttr(s.name)}">🗑️</button>
        </div>
      </li>`
    )
    .join("");
}

function escapeHtml(str) {
  return str.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function escapeAttr(str) {
  return escapeHtml(str);
}

// ----------------------- ações -----------------------
async function guarded(fn, errEl = "workError") {
  try {
    $(errEl).textContent = "";
    await fn();
  } catch (e) {
    const msg = typeof e === "string" ? e : e?.message || String(e);
    if (msg.includes("cancel")) return; // cancelamento de diálogo é silencioso
    $(errEl).textContent = msg;
    toast(msg, true);
  }
}

function password() {
  return $("password").value || null;
}

// ----------------------- wiring -----------------------
window.addEventListener("DOMContentLoaded", () => {
  // Progresso de adição de arquivos (evento emitido pelo backend).
  if (tauriEvent && tauriEvent.listen) {
    tauriEvent.listen("add-progress", (e) => {
      const { file, done, total } = e.payload || {};
      const pct = total ? Math.round((done / total) * 100) : 0;
      toast(
        `⏳ Adicionando ${file} — ${pct}%  (${fmtBytes(done)} / ${fmtBytes(total)})`,
        false,
        true
      );
    });
  }

  $("btnOpen").addEventListener("click", () =>
    guarded(async () => {
      toast("⏳ Abrindo cofre…", false, true);
      const info = await call("open_vault", { password: password() });
      render(info);
      toast("cofre aberto");
    }, "welcomeError")
  );

  $("btnCreate").addEventListener("click", () =>
    guarded(async () => {
      toast("⏳ Criando cofre…", false, true);
      const info = await call("create_vault", { password: password() });
      render(info);
      toast("cofre criado");
    }, "welcomeError")
  );

  $("btnClose").addEventListener("click", () =>
    guarded(async () => {
      await call("close_vault");
      showWelcome();
    })
  );

  $("btnAdd").addEventListener("click", () =>
    guarded(async () => {
      toast("⏳ Adicionando… arquivos grandes podem levar um tempo", false, true);
      const info = await call("add_files");
      render(info);
      toast("arquivos adicionados");
    })
  );

  $("btnGc").addEventListener("click", () =>
    guarded(async () => {
      toast("⏳ Compactando…", false, true);
      const info = await call("gc_vault");
      render(info);
      toast("container compactado");
    })
  );

  $("btnMount").addEventListener("click", () =>
    guarded(async () => {
      const isWin = navigator.userAgent.includes("Windows");
      const def = isWin ? "X:" : "/mnt/fsm";
      const hint = isWin
        ? "Letra de drive (ex: X:)"
        : "Diretório de montagem (ex: /mnt/fsm — deve existir)";
      const mp = prompt(hint, def);
      if (!mp) return;
      const at = await call("mount_drive", { mountpoint: mp });
      showMounted(at);
      toast(`montado em ${at}`);
    })
  );

  $("btnUnmount").addEventListener("click", () =>
    guarded(async () => {
      await call("unmount_drive");
      showWelcome();
      toast("desmontado");
    }, "mountError")
  );

  $("btnSnap").addEventListener("click", () =>
    guarded(async () => {
      const name = prompt("Nome do snapshot:");
      if (!name) return;
      const info = await call("snapshot_create", { name });
      render(info);
      toast(`snapshot "${name}" criado`);
    })
  );

  $("filter").addEventListener("input", (e) => {
    fileFilter = e.target.value;
    if (current) renderFiles(current.files);
  });

  // Delegação para ações das linhas de arquivo.
  $("fileList").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-act]");
    if (!btn) return;
    const path = btn.dataset.path;
    const act = btn.dataset.act;
    if (act === "extract") {
      guarded(async () => {
        const saved = await call("extract_file", { logical: path });
        if (saved) toast(`extraído para ${saved}`);
      });
    } else if (act === "remove") {
      guarded(async () => {
        if (!confirm(`Remover "${path}"?`)) return;
        const info = await call("remove_path", { logical: path, recursive: false });
        render(info);
        toast("removido");
      });
    }
  });

  // Delegação para ações de snapshot.
  $("snapList").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-snap-act]");
    if (!btn) return;
    const name = btn.dataset.name;
    const act = btn.dataset.snapAct;
    if (act === "restore") {
      guarded(async () => {
        if (!confirm(`Restaurar a árvore para o snapshot "${name}"? Isso substitui os arquivos atuais.`)) return;
        const info = await call("snapshot_restore", { name });
        render(info);
        toast(`restaurado para "${name}"`);
      });
    } else if (act === "delete") {
      guarded(async () => {
        if (!confirm(`Apagar o snapshot "${name}"?`)) return;
        const info = await call("snapshot_delete", { name });
        render(info);
        toast("snapshot apagado");
      });
    }
  });
});
