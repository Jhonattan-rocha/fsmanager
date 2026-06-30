const { invoke } = window.__TAURI__.core;
const tauriEvent = window.__TAURI__.event;

// ----------------------- estado -----------------------
let vaultOpen = false;
let currentPath = "/";
let lastInfo = null;
let lastEntries = []; // entradas atualmente renderizadas (ordem visível)
let selected = new Set(); // nomes selecionados na pasta atual
let lastClickedName = null; // âncora p/ seleção com Shift
let clipboard = []; // caminhos lógicos "recortados" para mover
let dragItems = []; // caminhos sendo arrastados (drag interno)

// ----------------------- utilidades -----------------------
function $(id) {
  return document.getElementById(id);
}

function fmtBytes(n) {
  if (n == null) return "—";
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
function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function joinPath(dir, name) {
  return dir === "/" ? `/${name}` : `${dir}/${name}`;
}

let toastTimer = null;
function toast(msg, isError = false, sticky = false) {
  const el = $("toast");
  el.textContent = msg;
  el.classList.toggle("error", isError);
  el.classList.remove("hidden");
  clearTimeout(toastTimer);
  if (!sticky) toastTimer = setTimeout(() => el.classList.add("hidden"), 3200);
}

async function call(cmd, args = {}) {
  return await invoke(cmd, args);
}

async function guarded(fn, errEl = "workError") {
  try {
    if ($(errEl)) $(errEl).textContent = "";
    await fn();
  } catch (e) {
    const msg = typeof e === "string" ? e : e?.message || String(e);
    if (msg.includes("cancel")) return; // cancelamento de diálogo é silencioso
    if ($(errEl)) $(errEl).textContent = msg;
    toast(msg, true);
  }
}

function password() {
  return $("password").value || null;
}

// ----------------------- telas -----------------------
function showWelcome() {
  vaultOpen = false;
  $("welcome").classList.remove("hidden");
  $("workspace").classList.add("hidden");
  $("mounted").classList.add("hidden");
  $("vaultPath").classList.add("hidden");
}
function showMounted(mountpoint) {
  vaultOpen = false;
  $("welcome").classList.add("hidden");
  $("workspace").classList.add("hidden");
  $("mounted").classList.remove("hidden");
  $("mountAt").textContent = mountpoint;
}
async function openWorkspace(info) {
  vaultOpen = true;
  lastInfo = info;
  currentPath = "/";
  $("welcome").classList.add("hidden");
  $("mounted").classList.add("hidden");
  $("workspace").classList.remove("hidden");
  $("vaultPath").textContent = info.path;
  $("vaultPath").classList.remove("hidden");
  renderStats(info.stats);
  renderSnapshots(info.snapshots);
  await navigate("/");
}

// ----------------------- navegação -----------------------
async function refresh() {
  const entries = await call("list_dir", { path: currentPath });
  renderBreadcrumbs(currentPath);
  renderFiles(entries);
  const info = await call("get_info");
  lastInfo = info;
  renderStats(info.stats);
  renderSnapshots(info.snapshots);
}
async function navigate(path) {
  currentPath = path || "/";
  clearSelection();
  await refresh();
}

function renderBreadcrumbs(path) {
  const el = $("breadcrumbs");
  const parts = path.split("/").filter(Boolean);
  let acc = "";
  let html = `<button class="crumb" data-path="/">🗄️ Cofre</button>`;
  for (const p of parts) {
    acc += `/${p}`;
    html += `<span class="crumb-sep">/</span><button class="crumb" data-path="${escapeHtml(acc)}">${escapeHtml(p)}</button>`;
  }
  el.innerHTML = html;
}

function renderFiles(entries) {
  const tbody = $("fileList");
  // Pastas primeiro, depois arquivos; cada grupo em ordem alfabética.
  const sorted = [...entries].sort((a, b) => {
    if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
  lastEntries = sorted;
  // Descarta da seleção nomes que não existem mais nesta pasta.
  selected = new Set([...selected].filter((n) => sorted.some((e) => e.name === n)));
  if (sorted.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">pasta vazia — arraste arquivos aqui ou use ➕ Adicionar</td></tr>`;
    updateBatchBar();
    return;
  }
  tbody.innerHTML = sorted
    .map((e) => {
      const icon = e.is_dir ? "📁" : "📄";
      const size = e.is_dir ? "—" : fmtBytes(e.size);
      const date = e.is_dir ? "—" : fmtDate(e.mtime);
      const sel = selected.has(e.name) ? " selected" : "";
      const actions = e.is_dir
        ? `<button class="small" data-act="rename">✏️</button><button class="small danger" data-act="remove">🗑️</button>`
        : `<button class="small" data-act="extract">⬇️</button><button class="small" data-act="rename">✏️</button><button class="small danger" data-act="remove">🗑️</button>`;
      return `<tr draggable="true" class="${sel}" data-name="${escapeHtml(e.name)}" data-dir="${e.is_dir ? 1 : 0}">
        <td class="name ${e.is_dir ? "is-dir" : ""}">${icon} ${escapeHtml(e.name)}</td>
        <td class="num">${size}</td>
        <td class="num dim">${date}</td>
        <td class="row-actions">${actions}</td>
      </tr>`;
    })
    .join("");
  updateBatchBar();
}

// ----------------------- seleção & ações em lote -----------------------
function fullPath(name) {
  return joinPath(currentPath, name);
}
function selectedPaths() {
  return [...selected].map(fullPath);
}
function clearSelection() {
  selected.clear();
  lastClickedName = null;
  applySelectionClasses();
}
function selectAll() {
  for (const e of lastEntries) selected.add(e.name);
  applySelectionClasses();
}
function applySelectionClasses() {
  for (const tr of $("fileList").querySelectorAll("tr[data-name]")) {
    tr.classList.toggle("selected", selected.has(tr.dataset.name));
  }
  updateBatchBar();
}
function updateBatchBar() {
  const n = selected.size;
  $("batchCount").textContent = `${n} selecionado${n === 1 ? "" : "s"}`;
  $("batchBar").classList.toggle("hidden", n === 0);
  const paste = $("btnPaste");
  paste.classList.toggle("hidden", clipboard.length === 0);
  if (clipboard.length) paste.textContent = `📋 Colar (${clipboard.length})`;
}
function handleRowSelect(name, e) {
  const names = lastEntries.map((x) => x.name);
  if (e.shiftKey && lastClickedName) {
    const a = names.indexOf(lastClickedName);
    const b = names.indexOf(name);
    if (a >= 0 && b >= 0) {
      if (!e.ctrlKey && !e.metaKey) selected.clear();
      const [lo, hi] = a < b ? [a, b] : [b, a];
      for (let i = lo; i <= hi; i++) selected.add(names[i]);
    }
  } else if (e.ctrlKey || e.metaKey) {
    selected.has(name) ? selected.delete(name) : selected.add(name);
    lastClickedName = name;
  } else {
    selected.clear();
    selected.add(name);
    lastClickedName = name;
  }
  applySelectionClasses();
}

function batchExtract() {
  const paths = selectedPaths();
  if (!paths.length) return;
  guarded(async () => {
    toast(`⏳ extraindo ${paths.length} arquivo(s)…`, false, true);
    const dest = await call("extract_files", { paths });
    if (dest) toast(`${paths.length} arquivo(s) extraído(s) para ${dest}`);
  });
}
function batchDelete() {
  const paths = selectedPaths();
  if (!paths.length) return;
  guarded(async () => {
    if (!confirm(`Excluir ${paths.length} item(ns) selecionado(s)? Pastas serão removidas com todo o conteúdo.`)) return;
    await call("remove_paths", { paths });
    clearSelection();
    await refresh();
    toast(`${paths.length} item(ns) removido(s)`);
  });
}
function batchMove() {
  clipboard = selectedPaths();
  if (!clipboard.length) return;
  toast(`✂️ ${clipboard.length} item(ns) recortado(s) — abra a pasta destino e clique em 📋 Colar`);
  clearSelection();
  updateBatchBar();
}
function doPaste() {
  if (!clipboard.length) return;
  const items = clipboard;
  guarded(async () => {
    await call("move_paths", { paths: items, destDir: currentPath });
    clipboard = [];
    await refresh();
    toast(`${items.length} item(ns) movido(s) para cá`);
  });
}
function clearDropTargets() {
  document.querySelectorAll(".drop-target").forEach((el) => el.classList.remove("drop-target"));
}

function renderStats(s) {
  const lock = s.encrypted ? "🔒 cifrado" : "🔓 aberto";
  const badges = [
    ["Arquivos", s.files],
    ["Blocos únicos", s.unique_blocks],
    ["Snapshots", s.snapshots],
    ["Lógico", fmtBytes(s.logical_bytes)],
    ["Em uso", s.quota ? `${fmtBytes(s.used_bytes)} / ${fmtBytes(s.quota)}` : fmtBytes(s.used_bytes)],
    ["Dedup", fmtPct(s.dedup_savings)],
    ["Compressão", fmtPct(s.compression_savings)],
    ["Economia total", fmtPct(s.total_savings)],
  ];
  $("stats").innerHTML =
    `<div class="badge state">${lock}</div>` +
    badges.map(([k, v]) => `<div class="badge"><span class="k">${k}</span><span class="v">${v}</span></div>`).join("");
}

function renderSnapshots(snaps) {
  const ul = $("snapList");
  if (!snaps || snaps.length === 0) {
    ul.innerHTML = `<li class="empty">nenhum snapshot</li>`;
    return;
  }
  ul.innerHTML = snaps
    .map(
      (sn) => `<li>
        <div class="snap-info">
          <span class="snap-name">${escapeHtml(sn.name)}</span>
          <span class="snap-meta">${sn.files} arq · ${fmtBytes(sn.size)} · ${fmtDate(sn.created)}</span>
        </div>
        <div class="snap-actions">
          <button class="small" data-snap-act="restore" data-name="${escapeHtml(sn.name)}">↩️</button>
          <button class="small danger" data-snap-act="delete" data-name="${escapeHtml(sn.name)}">🗑️</button>
        </div>
      </li>`
    )
    .join("");
}

// ----------------------- progresso -----------------------
function showProgress() {
  $("progress").classList.remove("hidden");
}
function hideProgress() {
  $("progress").classList.add("hidden");
  $("progressBar").style.width = "0%";
  $("progressLabel").textContent = "";
}

// ----------------------- gerenciar cofre -----------------------
function updateManageSize(s) {
  const used = (s && s.used_bytes) || 0;
  const quota = s && s.quota;
  if (quota) {
    const pct = Math.min(100, Math.round((used / quota) * 100));
    $("manageSize").textContent = `Usado ${fmtBytes(used)} de ${fmtBytes(quota)} (${pct}%)`;
    $("usageBar").style.width = `${pct}%`;
  } else {
    $("manageSize").textContent = `Usado ${fmtBytes(used)} — sem limite`;
    $("usageBar").style.width = "0%";
  }
}
function openManage() {
  const s = lastInfo && lastInfo.stats;
  $("manageEncStatus").textContent = s && s.encrypted ? "🔒 Cofre cifrado (com senha)." : "🔓 Cofre sem senha.";
  $("managePw").value = "";
  $("manageQuota").value = s && s.quota ? Math.round(s.quota / (1024 * 1024)) : "";
  $("manageError").textContent = "";
  updateManageSize(s);
  $("manageModal").classList.remove("hidden");
}
function closeManage() {
  $("manageModal").classList.add("hidden");
}

// ----------------------- menu de contexto -----------------------
function hideCtx() {
  $("ctxMenu").classList.add("hidden");
}
function showCtx(x, y, items) {
  const el = $("ctxMenu");
  el.innerHTML = items
    .map((it, i) => `<button data-i="${i}" class="${it.danger ? "danger" : ""}">${it.label}</button>`)
    .join("");
  el.style.left = `${x}px`;
  el.style.top = `${y}px`;
  el.classList.remove("hidden");
  el._items = items;
}

// ----------------------- edição inline (estilo Explorer) -----------------------
function startInlineNew() {
  const tbody = $("fileList");
  const tr = document.createElement("tr");
  tr.className = "editing-row";
  tr.innerHTML = `<td class="name is-dir">📁 <input class="inline-edit" placeholder="nome da pasta" /></td><td class="num">—</td><td class="num">—</td><td></td>`;
  tbody.prepend(tr);
  const input = tr.querySelector("input");
  input.focus();
  let done = false;
  const finish = async (save) => {
    if (done) return;
    done = true;
    const nome = input.value.trim();
    tr.remove();
    if (save && nome) {
      await guarded(async () => {
        await call("make_dir", { path: joinPath(currentPath, nome) });
        await refresh();
        toast("pasta criada");
      });
    }
  };
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") finish(true);
    else if (e.key === "Escape") finish(false);
  });
  input.addEventListener("blur", () => finish(true));
}

function startInlineRename(tr, name) {
  const cell = tr.querySelector("td.name");
  const icon = cell.textContent.trim().charAt(0); // 📁 ou 📄 (1º caractere)
  cell.innerHTML = `${icon} <input class="inline-edit" />`;
  const input = cell.querySelector("input");
  input.value = name;
  input.focus();
  input.select();
  let done = false;
  const finish = async (save) => {
    if (done) return;
    done = true;
    const novo = input.value.trim();
    if (save && novo && novo !== name) {
      await guarded(async () => {
        await call("rename_path", { from: joinPath(currentPath, name), to: joinPath(currentPath, novo) });
        await refresh();
        toast("renomeado");
      });
    } else {
      await refresh(); // restaura a célula
    }
  };
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") finish(true);
    else if (e.key === "Escape") finish(false);
  });
  input.addEventListener("blur", () => finish(true));
}

// ----------------------- ações de entrada -----------------------
function entryActions(name, isDir) {
  const full = joinPath(currentPath, name);
  return {
    open: () => navigate(full),
    extract: () =>
      guarded(async () => {
        const saved = await call("extract_file", { logical: full });
        if (saved) toast(`extraído para ${saved}`);
      }),
    rename: () => {
      const tr = [...$("fileList").querySelectorAll("tr[data-name]")].find((r) => r.dataset.name === name);
      if (tr) startInlineRename(tr, name);
    },
    remove: () =>
      guarded(async () => {
        const what = isDir ? `a pasta "${name}" e tudo dentro dela` : `"${name}"`;
        if (!confirm(`Remover ${what}?`)) return;
        await call("remove_path", { logical: full, recursive: isDir });
        await refresh();
        toast("removido");
      }),
  };
}

// ----------------------- wiring -----------------------
window.addEventListener("DOMContentLoaded", () => {
  // Progresso de adição.
  if (tauriEvent && tauriEvent.listen) {
    tauriEvent.listen("add-progress", (e) => {
      const { file, done, total } = e.payload || {};
      const pct = total ? Math.round((done / total) * 100) : 0;
      showProgress();
      $("progressBar").style.width = `${pct}%`;
      $("progressLabel").textContent = `Adicionando ${file} — ${pct}% (${fmtBytes(done)} / ${fmtBytes(total)})`;
    });

    // Arrastar-e-soltar arquivos (nomes de evento variam entre versões do Tauri).
    const onDragEnter = () => {
      if (vaultOpen) $("dropOverlay").classList.remove("hidden");
    };
    const onDragLeave = () => $("dropOverlay").classList.add("hidden");
    const onDrop = (e) => {
      $("dropOverlay").classList.add("hidden");
      if (!vaultOpen) return;
      // Payload pode ser { paths } (novo) ou um array de caminhos (antigo).
      const p = e.payload;
      const paths = Array.isArray(p) ? p : (p && p.paths) || [];
      if (!paths.length) return;
      const dest = currentPath;
      guarded(async () => {
        showProgress();
        try {
          const n = await call("add_dropped", { paths, destDir: dest });
          await refresh();
          if (n > 0) toast(`${n} item(ns) adicionado(s)`);
        } finally {
          hideProgress();
        }
      });
    };
    ["tauri://drag-enter", "tauri://file-drop-hover"].forEach((ev) => tauriEvent.listen(ev, onDragEnter));
    ["tauri://drag-leave", "tauri://file-drop-cancelled"].forEach((ev) => tauriEvent.listen(ev, onDragLeave));
    ["tauri://drag-drop", "tauri://file-drop"].forEach((ev) => tauriEvent.listen(ev, onDrop));
  }

  // --- welcome ---
  $("btnOpen").addEventListener("click", () =>
    guarded(async () => {
      toast("⏳ Abrindo cofre…", false, true);
      const info = await call("open_vault", { password: password() });
      await openWorkspace(info);
      toast("cofre aberto");
    }, "welcomeError")
  );
  $("btnCreate").addEventListener("click", () =>
    guarded(async () => {
      toast("⏳ Criando cofre…", false, true);
      const info = await call("create_vault", { password: password() });
      await openWorkspace(info);
      toast("cofre criado");
    }, "welcomeError")
  );

  // --- toolbar ---
  $("btnClose").addEventListener("click", () =>
    guarded(async () => {
      await call("close_vault");
      showWelcome();
    })
  );
  $("btnAdd").addEventListener("click", () =>
    guarded(async () => {
      const dest = currentPath;
      showProgress();
      try {
        const n = await call("add_files", { destDir: dest });
        await refresh();
        if (n > 0) toast(`${n} arquivo(s) adicionado(s)`);
      } finally {
        hideProgress();
      }
    })
  );
  $("btnNewFolder").addEventListener("click", () => {
    if (vaultOpen) startInlineNew();
  });
  $("btnPaste").addEventListener("click", doPaste);

  // --- barra de ações em lote ---
  $("batchExtract").addEventListener("click", batchExtract);
  $("batchMove").addEventListener("click", batchMove);
  $("batchDelete").addEventListener("click", batchDelete);
  $("batchClear").addEventListener("click", clearSelection);

  // --- atalhos de teclado ---
  window.addEventListener("keydown", (e) => {
    if (!vaultOpen) return;
    if (!$("workspace").contains(document.activeElement) && document.activeElement !== document.body) return;
    const typing = /^(INPUT|TEXTAREA)$/.test(document.activeElement?.tagName || "");
    if (typing) return;
    if (e.key === "Escape") {
      clearSelection();
    } else if (e.key === "Delete" && selected.size) {
      e.preventDefault();
      batchDelete();
    } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "a") {
      e.preventDefault();
      selectAll();
    } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "x" && selected.size) {
      e.preventDefault();
      batchMove();
    } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "v" && clipboard.length) {
      e.preventDefault();
      doPaste();
    }
  });

  // --- gerenciar cofre ---
  $("btnManage").addEventListener("click", () => {
    if (vaultOpen) openManage();
  });
  $("manageClose").addEventListener("click", closeManage);
  $("applyPw").addEventListener("click", () =>
    guarded(async () => {
      const pw = $("managePw").value;
      toast(`⏳ ${pw ? "Aplicando senha" : "Removendo senha"}… re-encriptando o cofre`, false, true);
      await call("change_password", { newPassword: pw || null });
      await refresh();
      openManage();
      toast(pw ? "senha definida" : "senha removida");
    }, "manageError")
  );
  $("applyQuota").addEventListener("click", () =>
    guarded(async () => {
      const mb = parseFloat($("manageQuota").value);
      if (!isFinite(mb) || mb <= 0) {
        $("manageError").textContent = "informe um valor em MB maior que zero";
        return;
      }
      await call("set_quota", { bytes: Math.round(mb * 1024 * 1024) });
      await refresh();
      updateManageSize(lastInfo.stats);
      toast("limite aplicado");
    }, "manageError")
  );
  $("clearQuota").addEventListener("click", () =>
    guarded(async () => {
      await call("set_quota", { bytes: null });
      await refresh();
      $("manageQuota").value = "";
      updateManageSize(lastInfo.stats);
      toast("limite removido");
    }, "manageError")
  );
  $("verifyBtn").addEventListener("click", () =>
    guarded(async () => {
      const out = $("verifyResult");
      out.className = "sub";
      out.textContent = "⏳ verificando todos os blocos…";
      const r = await call("verify_vault");
      if (r.healthy) {
        out.className = "sub ok";
        out.textContent = `✓ íntegro — ${r.blocks_ok} blocos verificados`;
      } else {
        out.className = "sub error";
        const det = r.errors.slice(0, 3).join("; ");
        out.textContent = `✗ ${r.blocks_bad} ruim(ns), ${r.missing_blocks} ausente(s)${det ? " — " + det : ""} — use 🔧 Reparar`;
      }
    }, "manageError")
  );
  $("repairBtn").addEventListener("click", () =>
    guarded(async () => {
      if (!confirm("Reparar trunca/remove arquivos com blocos corrompidos (o dado corrompido é perdido). Continuar?")) return;
      const out = $("verifyResult");
      out.className = "sub";
      out.textContent = "⏳ reparando…";
      const r = await call("repair_vault");
      await refresh();
      if (r.files_damaged === 0) {
        out.className = "sub ok";
        out.textContent = "✓ nada a reparar — cofre íntegro";
      } else {
        out.className = "sub";
        out.textContent = `${r.files_damaged} arquivo(s): ${r.truncated.length} truncado(s), ${r.removed.length} removido(s). Rode 🧹 Compactar para liberar espaço.`;
      }
    }, "manageError")
  );
  $("btnGc").addEventListener("click", () =>
    guarded(async () => {
      toast("⏳ Compactando…", false, true);
      await call("gc_vault");
      await refresh();
      toast("container compactado");
    })
  );
  $("btnMount").addEventListener("click", () =>
    guarded(async () => {
      const isWin = navigator.userAgent.includes("Windows");
      const def = isWin ? "X:" : "/mnt/fsm";
      const hint = isWin ? "Letra de drive (ex: X:)" : "Diretório de montagem (ex: /mnt/fsm — deve existir)";
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
      await call("snapshot_create", { name });
      await refresh();
      toast(`snapshot "${name}" criado`);
    })
  );

  // --- breadcrumbs ---
  $("breadcrumbs").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-path]");
    if (btn) guarded(() => navigate(btn.dataset.path));
  });
  $("breadcrumbs").addEventListener("dragover", (e) => {
    if (!dragItems.length) return;
    const btn = e.target.closest("button[data-path]");
    if (btn) {
      e.preventDefault();
      btn.classList.add("drop-target");
    }
  });
  $("breadcrumbs").addEventListener("dragleave", (e) => {
    e.target.closest("button[data-path]")?.classList.remove("drop-target");
  });
  $("breadcrumbs").addEventListener("drop", (e) => {
    const btn = e.target.closest("button[data-path]");
    if (!dragItems.length || !btn) return;
    e.preventDefault();
    btn.classList.remove("drop-target");
    const dest = btn.dataset.path;
    const items = dragItems;
    dragItems = [];
    if (dest === currentPath) return;
    guarded(async () => {
      await call("move_paths", { paths: items, destDir: dest });
      clearSelection();
      await refresh();
      toast("movido");
    });
  });

  // --- lista de arquivos: navegação, ações, menu de contexto ---
  $("fileList").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-act]");
    if (btn) {
      const tr = btn.closest("tr");
      const acts = entryActions(tr.dataset.name, tr.dataset.dir === "1");
      acts[btn.dataset.act]();
      return;
    }
    const tr = e.target.closest("tr[data-name]");
    if (!tr) return;
    handleRowSelect(tr.dataset.name, e);
  });

  // --- drag-and-drop INTERNO: mover itens para uma pasta/breadcrumb ---
  $("fileList").addEventListener("dragstart", (e) => {
    const tr = e.target.closest("tr[data-name]");
    if (!tr) return;
    const name = tr.dataset.name;
    if (!selected.has(name)) {
      selected.clear();
      selected.add(name);
      lastClickedName = name;
      applySelectionClasses();
    }
    dragItems = selectedPaths();
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("text/plain", dragItems.join("\n"));
  });
  $("fileList").addEventListener("dragover", (e) => {
    if (!dragItems.length) return;
    clearDropTargets();
    const tr = e.target.closest('tr[data-dir="1"]');
    if (tr && !selected.has(tr.dataset.name)) {
      e.preventDefault();
      tr.classList.add("drop-target");
    }
  });
  $("fileList").addEventListener("drop", (e) => {
    const tr = e.target.closest('tr[data-dir="1"]');
    clearDropTargets();
    if (!dragItems.length || !tr || selected.has(tr.dataset.name)) return;
    e.preventDefault();
    const destName = tr.dataset.name;
    const dest = joinPath(currentPath, destName);
    const items = dragItems;
    dragItems = [];
    guarded(async () => {
      await call("move_paths", { paths: items, destDir: dest });
      clearSelection();
      await refresh();
      toast(`movido para ${destName}`);
    });
  });
  $("fileList").addEventListener("dragend", () => {
    dragItems = [];
    clearDropTargets();
  });
  $("fileList").addEventListener("dblclick", (e) => {
    const tr = e.target.closest("tr[data-name]");
    if (!tr) return;
    const isDir = tr.dataset.dir === "1";
    const acts = entryActions(tr.dataset.name, isDir);
    isDir ? acts.open() : acts.extract();
  });
  $("fileList").addEventListener("contextmenu", (e) => {
    const tr = e.target.closest("tr[data-name]");
    if (!tr) return;
    e.preventDefault();
    const name = tr.dataset.name;
    // Clique direito sobre item fora da seleção: seleciona só ele.
    if (!selected.has(name)) {
      selected.clear();
      selected.add(name);
      lastClickedName = name;
      applySelectionClasses();
    }
    // Vários selecionados → menu em lote.
    if (selected.size > 1) {
      const n = selected.size;
      showCtx(e.clientX, e.clientY, [
        { label: `⬇️ Extrair ${n} itens`, fn: batchExtract },
        { label: `✂️ Mover ${n} itens`, fn: batchMove },
        { label: `🗑️ Excluir ${n} itens`, fn: batchDelete, danger: true },
      ]);
      return;
    }
    const isDir = tr.dataset.dir === "1";
    const acts = entryActions(name, isDir);
    const items = isDir
      ? [
          { label: "📂 Abrir", fn: acts.open },
          { label: "✏️ Renomear", fn: acts.rename },
          { label: "✂️ Mover", fn: batchMove },
          { label: "🗑️ Excluir", fn: acts.remove, danger: true },
        ]
      : [
          { label: "⬇️ Extrair", fn: acts.extract },
          { label: "✏️ Renomear", fn: acts.rename },
          { label: "✂️ Mover", fn: batchMove },
          { label: "🗑️ Excluir", fn: acts.remove, danger: true },
        ];
    showCtx(e.clientX, e.clientY, items);
  });
  $("ctxMenu").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-i]");
    if (!btn) return;
    const items = $("ctxMenu")._items || [];
    hideCtx();
    items[+btn.dataset.i]?.fn();
  });
  window.addEventListener("click", () => hideCtx());
  window.addEventListener("scroll", () => hideCtx(), true);

  // --- snapshots ---
  $("snapList").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-snap-act]");
    if (!btn) return;
    const name = btn.dataset.name;
    if (btn.dataset.snapAct === "restore") {
      guarded(async () => {
        if (!confirm(`Restaurar a árvore para o snapshot "${name}"? Isso substitui os arquivos atuais.`)) return;
        await call("snapshot_restore", { name });
        await navigate("/");
        toast(`restaurado para "${name}"`);
      });
    } else {
      guarded(async () => {
        if (!confirm(`Apagar o snapshot "${name}"?`)) return;
        await call("snapshot_delete", { name });
        await refresh();
        toast("snapshot apagado");
      });
    }
  });
});
