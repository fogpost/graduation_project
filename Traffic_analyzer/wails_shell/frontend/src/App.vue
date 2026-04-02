
<script setup>
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from "vue";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { ClipboardSetText, EventsOff, EventsOn } from "../wailsjs/runtime/runtime";
import "@xterm/xterm/css/xterm.css";

const API_BASE = "http://127.0.0.1:8000";
const POLL_INTERVAL_MS = 3000;

const serviceStatus = ref({ backend_running: false, capture_running: false });
const actionMessage = ref("");
const packets = ref([]);
const total = ref(0);
const listError = ref("");
const selectedPacketId = ref(null);
const detail = ref(null);
const detailError = ref("");
const fileItems = ref([]);
const currentFile = ref("");
const fileError = ref("");
const showFilePanel = ref(true);
const autoRefreshFiles = ref(true);
const autoParseLive = ref(true);
const report = ref({ packet_count: 0, feature_stats: { protocol_counts: [], unique_src_ips: 0, unique_dst_ips: 0 }, alerts: [] });
const expandedAlertIds = ref(new Set());
const highlightStart = ref(-1);
const highlightLength = ref(0);
const fileInputRef = ref(null);
const parsedLiveFiles = new Set();
let pollTimer = null;
let actionRunning = false;

const titleMenuOpen = ref(false);
const terminalVisible = ref(false);
const terminals = ref([]);
const activeTerminalId = ref("local-default");
const terminalHostRef = ref(null);
const sshHost = ref("");
const sshPort = ref(22);
const sshUser = ref("");
const sshPass = ref("");
const sshAuthMode = ref("password");
const sshKeyPath = ref("");
const sshKeyPassphrase = ref("");
const sshName = ref("");
const localTerminalName = ref("");
let terminalEmulator = null;
let fitAddon = null;
let terminalResizeObserver = null;
let fitTimer = null;
const terminalHistory = new Map();
const terminalDecoders = new Map();
const terminalLegacyDecoders = new Map();
const MAX_TERMINAL_HISTORY_CHARS = 500000;

const captureInterfaces = ref([]);
const selectedCaptureIfaceIndex = ref(-1);
const loadingIfaces = ref(false);

const hexBytes = computed(() => (detail.value?.raw_hex?.match(/.{1,2}/g) || []));
const hexRows = computed(() => {
  const rows = [];
  for (let i = 0; i < hexBytes.value.length; i += 16) rows.push(hexBytes.value.slice(i, i + 16));
  return rows;
});
const liveFiles = computed(() => fileItems.value.filter((f) => f.relative_path.toLowerCase().startsWith("live/")).sort((a, b) => a.modified_at - b.modified_at));
const activeTerminal = computed(() => terminals.value.find((t) => t.id === activeTerminalId.value));
const activeTerminalDisconnected = computed(() => Boolean(activeTerminal.value) && !activeTerminal.value.connected);
const selectedIfaceLabel = computed(() => captureInterfaces.value.find((i) => i.index === Number(selectedCaptureIfaceIndex.value))?.display || "自动选择");
const terminalUser = ref({ username: "", role: "viewer" });

async function callApp(method, ...args) {
  const fn = window?.go?.main?.App?.[method];
  if (!fn) throw new Error(`Wails binding missing: ${method}`);
  return fn(...args);
}

function clearHighlight() { highlightStart.value = -1; highlightLength.value = 0; }
function highlightField(offset, length) { highlightStart.value = offset; highlightLength.value = length; }
function isHighlighted(i) { return highlightStart.value >= 0 && highlightLength.value > 0 && i >= highlightStart.value && i < highlightStart.value + highlightLength.value; }
function toggleTitleMenu() { titleMenuOpen.value = !titleMenuOpen.value; }
async function toggleTerminal() {
  terminalVisible.value = !terminalVisible.value;
  titleMenuOpen.value = false;
  if (terminalVisible.value) {
    await refreshTerminals();
    await hydrateTerminalHistory(activeTerminalId.value);
    await nextTick();
    ensureTerminalEmulator();
    renderActiveTerminalFromHistory();
    scheduleFitTerminal();
    terminalEmulator?.focus();
  }
}

function decodeBase64ToBytes(base64Text) {
  const bin = atob(base64Text || "");
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

function fitTerminal() {
  if (!terminalEmulator || !fitAddon) return;
  fitAddon.fit();
  if (activeTerminalId.value) {
    callApp("ResizeTerminalByID", activeTerminalId.value, terminalEmulator.cols, terminalEmulator.rows).catch(() => {});
  }
}

function scheduleFitTerminal() {
  if (fitTimer) clearTimeout(fitTimer);
  fitTerminal();
  fitTimer = setTimeout(() => {
    fitTerminal();
    requestAnimationFrame(() => fitTerminal());
  }, 60);
}

function appendTerminalHistory(id, chunk) {
  if (!id || !chunk) return;
  const prev = terminalHistory.get(id) || "";
  let next = prev + chunk;
  if (next.length > MAX_TERMINAL_HISTORY_CHARS) {
    next = next.slice(next.length - MAX_TERMINAL_HISTORY_CHARS);
  }
  terminalHistory.set(id, next);
}

function renderActiveTerminalFromHistory() {
  if (!terminalEmulator || !activeTerminalId.value) return;
  terminalDecoders.set(activeTerminalId.value, new TextDecoder("utf-8"));
  terminalEmulator.clear();
  const text = terminalHistory.get(activeTerminalId.value) || "";
  if (text) terminalEmulator.write(text);
}

function getTerminalDecoder(id) {
  if (!terminalDecoders.has(id)) {
    terminalDecoders.set(id, new TextDecoder("utf-8", { fatal: true }));
  }
  return terminalDecoders.get(id);
}

function getTerminalLegacyDecoder(id) {
  if (!terminalLegacyDecoders.has(id)) {
    try {
      terminalLegacyDecoders.set(id, new TextDecoder("gb18030"));
    } catch {
      terminalLegacyDecoders.set(id, new TextDecoder("utf-8"));
    }
  }
  return terminalLegacyDecoders.get(id);
}

function decodeTerminalChunk(payload, bytes) {
  const id = payload?.id;
  const source = payload?.source;
  if (!id) return "";
  const utf8 = getTerminalDecoder(id);
  try {
    return utf8.decode(bytes, { stream: true });
  } catch {
    if (source === "local") {
      return getTerminalLegacyDecoder(id).decode(bytes, { stream: true });
    }
    return new TextDecoder("utf-8").decode(bytes);
  }
}

async function hydrateTerminalHistory(id) {
  if (!id) return;
  if ((terminalHistory.get(id) || "").length > 0) {
    if (id === activeTerminalId.value) renderActiveTerminalFromHistory();
    return;
  }
  try {
    const logs = await callApp("GetTerminalLogsByID", id, 1200);
    const text = Array.isArray(logs) ? logs.map((l) => `${l.line ?? ""}\r\n`).join("") : "";
    terminalHistory.set(id, text);
    if (id === activeTerminalId.value) {
      renderActiveTerminalFromHistory();
    }
  } catch {}
}

function ensureTerminalEmulator() {
  if (terminalEmulator || !terminalHostRef.value) return;
  terminalEmulator = new Terminal({
    convertEol: false,
    cursorBlink: true,
    fontFamily: "Consolas, 'Cascadia Mono', monospace",
    fontSize: 13,
    theme: {
      background: "#132a1d",
      foreground: "#d6f0df",
      cursor: "#d6f0df",
    },
  });
  fitAddon = new FitAddon();
  terminalEmulator.loadAddon(fitAddon);
  terminalEmulator.open(terminalHostRef.value);
  scheduleFitTerminal();
  terminalEmulator.focus();

  terminalEmulator.onData((input) => {
    if (!activeTerminalId.value) return;
    callApp("WriteTerminalInputByID", activeTerminalId.value, input)
      .then((status) => {
        if (status !== "sent" && status !== "empty") {
          actionMessage.value = `终端输入未送达: ${status}`;
        }
      })
      .catch((e) => {
        actionMessage.value = `终端输入失败: ${e}`;
      });
  });

  terminalResizeObserver = new ResizeObserver(() => scheduleFitTerminal());
  terminalResizeObserver.observe(terminalHostRef.value);
}

async function kickTerminalPrompt(id) {
  if (!id) return;
  try {
    await callApp("WriteTerminalInputByID", id, "\r");
  } catch {}
}

function resetTerminalEmulator() {
  if (!terminalEmulator) return;
  terminalEmulator.clear();
}

function onTerminalStream(payload) {
  if (!payload || !payload.id) return;
  try {
    const bytes = decodeBase64ToBytes(payload.data_b64);
    const text = decodeTerminalChunk(payload, bytes);
    if (!text) return;
    appendTerminalHistory(payload.id, text);
    if (!terminalVisible.value || payload.id !== activeTerminalId.value) return;
    ensureTerminalEmulator();
    if (!terminalEmulator) return;
    terminalEmulator.write(text);
  } catch {}
}

function toggleAlertExpand(id) { const s = new Set(expandedAlertIds.value); s.has(id) ? s.delete(id) : s.add(id); expandedAlertIds.value = s; }
function isAlertExpanded(id) { return expandedAlertIds.value.has(id); }
function evidencePairs(e = {}) { return Object.entries(e).filter(([k]) => !["packet_ids", "primary_packet_id"].includes(k)); }
async function locateAlertPacket(a) {
  const id = a?.evidence?.primary_packet_id;
  if (id === undefined || id === null) return;
  await loadPackets();
  await selectPacket(id);
  actionMessage.value = `已定位到包 #${id}`;
}

async function refreshCaptureInterfaces() {
  loadingIfaces.value = true;
  try {
    const items = await callApp("ListCaptureInterfaces");
    captureInterfaces.value = Array.isArray(items) ? items : [];
    if (!captureInterfaces.value.some((x) => x.index === Number(selectedCaptureIfaceIndex.value))) {
      const preferred = captureInterfaces.value.find((x) => (x.ips || []).length > 0 && !(x.display || "").toLowerCase().includes("loopback"));
      selectedCaptureIfaceIndex.value = preferred ? preferred.index : captureInterfaces.value[0]?.index ?? -1;
    }
  } catch (e) { actionMessage.value = `网卡列表获取失败: ${e}`; } finally { loadingIfaces.value = false; }
}

async function refreshServiceStatus() { try { serviceStatus.value = await callApp("ServiceStatus"); } catch (e) { actionMessage.value = `状态获取失败: ${e}`; } }
async function startEmbeddedStack() { try { serviceStatus.value = { ...serviceStatus.value, ...(await callApp("StartEmbeddedStack")) }; } catch (e) { actionMessage.value = `启动失败: ${e}`; } }
async function stopEmbeddedStack() { try { serviceStatus.value = await callApp("StopEmbeddedStack"); } catch (e) { actionMessage.value = `停止失败: ${e}`; } }
async function startCapture() {
  try {
    const idx = Number(selectedCaptureIfaceIndex.value);
    if (Number.isInteger(idx) && idx >= 0) await callApp("StartCaptureWithInterface", idx, "");
    else await callApp("StartCapture");
    await refreshServiceStatus();
    actionMessage.value = `抓包启动: ${selectedIfaceLabel.value}`;
  } catch (e) { actionMessage.value = `抓包启动失败: ${e}`; }
}
async function stopCapture() { try { await callApp("StopCapture"); await refreshServiceStatus(); } catch (e) { actionMessage.value = `抓包停止失败: ${e}`; } }

async function refreshAnalysis() { try { const r = await fetch(`${API_BASE}/analysis/report`); if (!r.ok) throw new Error(`HTTP ${r.status}`); report.value = await r.json(); } catch (e) { actionMessage.value = `检测刷新失败: ${e}`; } }
async function refreshFileCatalog(s = false) { if (!s) fileError.value = ""; try { const r = await fetch(`${API_BASE}/pcap-files`); if (!r.ok) throw new Error(`HTTP ${r.status}`); const d = await r.json(); fileItems.value = d.items || []; currentFile.value = d.current_file || ""; } catch (e) { fileError.value = `加载文件列表失败: ${e}`; } }
async function loadPackets() {
  listError.value = "";
  try {
    const r = await fetch(`${API_BASE}/packets?offset=0&limit=1000`); if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const d = await r.json(); packets.value = d.items || []; total.value = d.total || packets.value.length;
    if (!packets.value.length) { selectedPacketId.value = null; detail.value = null; return; }
    const stillExists = packets.value.some((p) => p.id === selectedPacketId.value);
    if (!stillExists) await selectPacket(packets.value[0].id);
    else if (selectedPacketId.value !== null && selectedPacketId.value !== undefined) await selectPacket(selectedPacketId.value);
  } catch (e) { listError.value = `加载列表失败: ${e}`; }
}
async function selectPacket(id) {
  selectedPacketId.value = id; detailError.value = ""; clearHighlight();
  try { const r = await fetch(`${API_BASE}/packet/${id}/detail`); if (!r.ok) throw new Error(`HTTP ${r.status}`); detail.value = await r.json(); }
  catch (e) { detail.value = null; detailError.value = `加载详情失败: ${e}`; }
}

async function loadDataFile(path, { silent = false } = {}) {
  if (actionRunning) return;
  actionRunning = true;
  try {
    const r = await fetch(`${API_BASE}/load-data-file?relative_path=${encodeURIComponent(path)}`, { method: "POST" });
    if (!r.ok) throw new Error((await r.text()) || `HTTP ${r.status}`);
    const d = await r.json();
    parsedLiveFiles.add(path);
    if (!silent) actionMessage.value = `已加载: ${d.file}`;
    await refreshFileCatalog(true); await loadPackets(); await refreshAnalysis();
  } catch (e) { actionMessage.value = `文件加载失败: ${e}`; } finally { actionRunning = false; }
}

async function deleteDataFile(path) {
  if (!path) return;
  if (!window.confirm(`确认删除文件？\n${path}`)) return;
  try {
    const r = await fetch(`${API_BASE}/data-file?relative_path=${encodeURIComponent(path)}`, { method: "DELETE" });
    if (!r.ok) throw new Error((await r.text()) || `HTTP ${r.status}`);
    await refreshFileCatalog(true); await loadPackets(); await refreshAnalysis();
    actionMessage.value = `已删除文件: ${path}`;
  } catch (e) { actionMessage.value = `删除文件失败: ${e}`; }
}

async function deleteSelectedPacket() {
  if (selectedPacketId.value === null || selectedPacketId.value === undefined) return;
  if (!window.confirm(`确认删除当前选中包 #${selectedPacketId.value} 吗？`)) return;
  try {
    const r = await fetch(`${API_BASE}/packet/${selectedPacketId.value}`, { method: "DELETE" });
    if (!r.ok) throw new Error((await r.text()) || `HTTP ${r.status}`);
    selectedPacketId.value = null; detail.value = null;
    await loadPackets(); await refreshAnalysis();
    actionMessage.value = "已删除选中包";
  } catch (e) { actionMessage.value = `删除包失败: ${e}`; }
}

async function loadNextDataFile() {
  if (actionRunning) return;
  actionRunning = true;
  try {
    const r = await fetch(`${API_BASE}/load-next-data-file`, { method: "POST" });
    if (!r.ok) throw new Error((await r.text()) || `HTTP ${r.status}`);
    const d = await r.json(); if (d.relative_path) parsedLiveFiles.add(d.relative_path);
    await refreshFileCatalog(true); await loadPackets(); await refreshAnalysis();
  } catch (e) { actionMessage.value = `顺序解析失败: ${e}`; } finally { actionRunning = false; }
}

function triggerImport() { if (!fileInputRef.value) return; fileInputRef.value.value = ""; fileInputRef.value.click(); }
async function onImportFileChange(e) {
  const file = e.target.files?.[0]; if (!file || actionRunning) return;
  actionRunning = true;
  try {
    const form = new FormData(); form.append("file", file);
    const r = await fetch(`${API_BASE}/upload-pcap`, { method: "POST", body: form });
    if (!r.ok) throw new Error((await r.text()) || `HTTP ${r.status}`);
    await refreshFileCatalog(true); await loadPackets(); await refreshAnalysis();
  } catch (err) { actionMessage.value = `导包失败: ${err}`; } finally { actionRunning = false; }
}

function nextUnparsedLiveFile() { return liveFiles.value.find((f) => !parsedLiveFiles.has(f.relative_path)); }

async function refreshTerminals() {
  try {
    terminals.value = await callApp("ListTerminals");
    if (!terminals.value.find((t) => t.id === activeTerminalId.value) && terminals.value.length) activeTerminalId.value = terminals.value[0].id;
  } catch (e) { actionMessage.value = `终端列表获取失败: ${e}`; }
}

async function refreshCurrentTerminalUser() {
  try {
    terminalUser.value = await callApp("GetCurrentTerminalUser");
  } catch {}
}

async function createLocalTerminal() {
  try {
    actionMessage.value = "正在创建本地终端...";
    const i = await callApp("CreateLocalTerminal", localTerminalName.value.trim());
    localTerminalName.value = "";
    terminals.value = [...terminals.value.filter((t) => t.id !== i.id), i];
    activeTerminalId.value = i.id;
    await nextTick();
    ensureTerminalEmulator();
    await hydrateTerminalHistory(i.id);
    await kickTerminalPrompt(i.id);
    fitTerminal();
    terminalEmulator?.focus();
    actionMessage.value = `本地终端已创建: ${i.name} (${i.id})`;
    setTimeout(() => { refreshTerminals(); }, 250);
  } catch (e) { actionMessage.value = `创建本地终端失败: ${e}`; }
}
async function createSshTerminal() {
  try {
    actionMessage.value = "正在创建SSH终端...";
    const i = await callApp(
      "CreateSSHTerminalWithKey",
      sshHost.value.trim(),
      Number(sshPort.value || 22),
      sshUser.value.trim(),
      sshAuthMode.value === "password" ? sshPass.value : "",
      sshAuthMode.value === "rsa" ? sshKeyPath.value.trim() : "",
      sshAuthMode.value === "rsa" ? sshKeyPassphrase.value : "",
      sshName.value.trim(),
    );
    sshPass.value = "";
    sshKeyPassphrase.value = "";
    terminals.value = [...terminals.value.filter((t) => t.id !== i.id), i];
    activeTerminalId.value = i.id;
    await nextTick();
    ensureTerminalEmulator();
    await hydrateTerminalHistory(i.id);
    await kickTerminalPrompt(i.id);
    fitTerminal();
    terminalEmulator?.focus();
    actionMessage.value = `SSH终端已创建: ${i.name} (${i.id})`;
    setTimeout(() => { refreshTerminals(); }, 250);
  } catch (e) { actionMessage.value = `创建SSH终端失败: ${e}`; }
}
async function closeActiveTerminal() {
  if (!activeTerminalId.value || activeTerminalId.value === "local-default") return;
  const closedID = activeTerminalId.value;
  await callApp("CloseTerminal", closedID);
  terminalHistory.delete(closedID);
  terminalDecoders.delete(closedID);
  terminalLegacyDecoders.delete(closedID);
  await refreshTerminals();
  if (!terminals.value.find((t) => t.id === activeTerminalId.value)) {
    activeTerminalId.value = "local-default";
  }
}

async function reconnectActiveTerminal() {
  if (!activeTerminalId.value) return;
  try {
    actionMessage.value = `正在重连终端 ${activeTerminalId.value}...`;
    const status = await callApp("WriteTerminalInputByID", activeTerminalId.value, "\r");
    await refreshTerminals();
    await hydrateTerminalHistory(activeTerminalId.value);
    await nextTick();
    ensureTerminalEmulator();
    renderActiveTerminalFromHistory();
    scheduleFitTerminal();
    terminalEmulator?.focus();
    actionMessage.value = status === "sent" ? "终端已重连" : `终端重连状态: ${status}`;
  } catch (e) {
    actionMessage.value = `终端重连失败: ${e}`;
  }
}

async function copyActiveTerminalText() {
  const selected = terminalEmulator?.getSelection?.() || "";
  const fallback = activeTerminalId.value ? (terminalHistory.get(activeTerminalId.value) || "") : "";
  const text = selected || fallback;
  if (!text) {
    actionMessage.value = "当前没有可复制的终端内容";
    return;
  }
  try {
    await ClipboardSetText(text);
    actionMessage.value = selected ? "已复制选中终端内容" : "已复制当前终端历史输出";
  } catch (e) {
    actionMessage.value = `复制失败: ${e}`;
  }
}

async function pollingTick() {
  if (autoRefreshFiles.value) await refreshFileCatalog(true);
  if (autoParseLive.value && !actionRunning) { const next = nextUnparsedLiveFile(); if (next) await loadDataFile(next.relative_path, { silent: true }); }
  await refreshServiceStatus(); await refreshAnalysis();
}

function startPolling() { stopPolling(); pollTimer = setInterval(() => { pollingTick(); }, POLL_INTERVAL_MS); }
function stopPolling() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }

async function init() {
  await startEmbeddedStack(); await refreshCaptureInterfaces(); await refreshFileCatalog(); await loadPackets(); await refreshAnalysis();
  await refreshServiceStatus(); await refreshTerminals(); await refreshCurrentTerminalUser(); startPolling();
  await hydrateTerminalHistory(activeTerminalId.value);
  EventsOn("terminal:stream", onTerminalStream);
}

watch(activeTerminalId, async () => {
  await hydrateTerminalHistory(activeTerminalId.value);
  resetTerminalEmulator();
  renderActiveTerminalFromHistory();
  scheduleFitTerminal();
  terminalEmulator?.focus();
});
onMounted(async () => { await init(); });
onUnmounted(() => {
  stopPolling();
  EventsOff("terminal:stream");
  if (fitTimer) {
    clearTimeout(fitTimer);
    fitTimer = null;
  }
  if (terminalResizeObserver) {
    terminalResizeObserver.disconnect();
    terminalResizeObserver = null;
  }
  if (terminalEmulator) {
    terminalEmulator.dispose();
    terminalEmulator = null;
    fitAddon = null;
  }
  terminalDecoders.clear();
  terminalLegacyDecoders.clear();
});
</script>

<template>
  <div class="app">
    <header class="header">
      <div class="title" @click="toggleTitleMenu">Traffic Analyzer Desktop</div>
      <div class="title-menu" v-if="titleMenuOpen"><button @click="toggleTerminal">终端中心</button></div>
      <div class="toolbar">
        <button @click="startEmbeddedStack">启动后端</button><button class="danger" @click="stopEmbeddedStack">停止后端</button>
        <button @click="startCapture">启动抓包</button><button class="danger" @click="stopCapture">停止抓包</button><button @click="refreshAnalysis">刷新检测</button>
      </div>
      <div class="flags"><span :class="['dot', serviceStatus.backend_running ? 'on' : 'off']"></span>后端 <span :class="['dot', serviceStatus.capture_running ? 'on' : 'off']"></span>抓包</div>
    </header>

    <input ref="fileInputRef" type="file" accept=".pcap,.pcapng,.cap" style="display:none" @change="onImportFileChange" />

    <main class="layout">
      <aside class="sidebar">
        <section class="card">
          <h3>运行状态</h3>
          <div class="hint">{{ actionMessage || '就绪' }}</div>
          <div class="hint truncate" :title="serviceStatus.project_root">项目: {{ serviceStatus.project_root }}</div>
          <div class="hint truncate" :title="serviceStatus.data_dir">数据: {{ serviceStatus.data_dir }}</div>
          <label><input v-model="autoRefreshFiles" type="checkbox"/> 自动刷新</label>
          <label><input v-model="autoParseLive" type="checkbox"/> 自动轮询</label>
        </section>

        <section class="card">
          <h3>抓包网卡</h3>
          <div class="row"><select v-model.number="selectedCaptureIfaceIndex"><option :value="-1">自动选择</option><option v-for="i in captureInterfaces" :key="i.index" :value="i.index">{{ i.display }}</option></select><button @click="refreshCaptureInterfaces" :disabled="loadingIfaces">刷新</button></div>
          <div class="hint" :title="selectedIfaceLabel">当前: {{ selectedIfaceLabel }}</div>
        </section>

        <section class="card">
          <h3>检测结果</h3>
          <div class="grid4"><div>包数 <b>{{ report.packet_count || 0 }}</b></div><div>告警 <b>{{ report.alerts?.length || 0 }}</b></div><div>源IP <b>{{ report.feature_stats?.unique_src_ips || 0 }}</b></div><div>目的IP <b>{{ report.feature_stats?.unique_dst_ips || 0 }}</b></div></div>
          <div class="mini" v-for="p in report.feature_stats?.protocol_counts || []" :key="p.key">{{ p.key }}: {{ p.count }}</div>
        </section>

        <section class="card alerts">
          <h3>告警列表</h3>
          <div v-if="!(report.alerts?.length)">暂无告警</div>
          <div v-for="a in report.alerts || []" :key="a.alert_id" class="alert" :data-level="a.severity">
            <div class="alert-head"><b>{{ a.alert_id }} · {{ a.title }}</b><span><button @click="toggleAlertExpand(a.alert_id)">{{ isAlertExpanded(a.alert_id) ? '收起' : '证据' }}</button><button @click="locateAlertPacket(a)" :disabled="a?.evidence?.primary_packet_id===undefined || a?.evidence?.primary_packet_id===null">定位包</button></span></div>
            <div v-if="a.alert_ip">告警IP: {{ a.alert_ip }}</div>
            <div>{{ a.description }}</div><div>建议: {{ a.recommendation }}</div>
            <div v-if="isAlertExpanded(a.alert_id)" class="evidence"><div v-for="[k,v] in evidencePairs(a.evidence)" :key="`${a.alert_id}-${k}`">{{ k }}: {{ Array.isArray(v) ? v.join(', ') : v }}</div><div v-if="a?.evidence?.packet_ids?.length">packet_ids: {{ a.evidence.packet_ids.slice(0,12).join(', ') }}</div></div>
          </div>
        </section>
      </aside>
      <section class="main-panel">
        <div class="panel-top"><button @click="loadPackets">刷新列表</button><button @click="triggerImport">导包</button><button @click="showFilePanel=!showFilePanel">文件列表</button><button @click="loadNextDataFile">解析下一个</button><button class="danger" @click="deleteSelectedPacket">删除选中包</button><span class="current-file" :title="currentFile">当前: {{ currentFile || '未加载' }}</span><span>总包数: {{ total }}</span></div>
        <div class="error" v-if="listError || fileError">{{ listError || fileError }}</div>
        <div class="main-grid">
          <div class="list-area">
            <div class="file-panel" v-if="showFilePanel"><div v-for="f in fileItems" :key="f.relative_path"><button @click="loadDataFile(f.relative_path)">[{{ f.index }}] {{ f.relative_path }}</button><button class="danger" @click="deleteDataFile(f.relative_path)">删除</button></div></div>
            <div class="table-wrap"><table><thead><tr><th style="width:54px">No</th><th style="width:82px">协议</th><th>源IP</th><th>目的IP</th><th style="width:86px">源端口</th><th style="width:86px">目的端口</th><th style="width:78px">长度</th></tr></thead><tbody><tr v-for="p in packets" :key="p.id" :class="{selected:p.id===selectedPacketId}" @click="selectPacket(p.id)"><td>{{ p.id }}</td><td>{{ p.protocol || '-' }}</td><td :title="p.src_ip">{{ p.src_ip || '-' }}</td><td :title="p.dst_ip">{{ p.dst_ip || '-' }}</td><td>{{ p.src_port ?? '-' }}</td><td>{{ p.dst_port ?? '-' }}</td><td>{{ p.length }}</td></tr></tbody></table></div>
          </div>
          <div class="detail-area">
            <div v-if="detailError" class="error">{{ detailError }}</div><div v-else-if="!detail" class="hint">请选择数据包</div>
            <div v-else class="detail-grid">
              <div class="parse-pane"><div class="sub">解析数据</div><div class="parse-scroll"><div class="layer" v-for="layer in detail.layers" :key="`${layer.layer_name}-${layer.start}`"><div class="layer-head" @mouseover="highlightField(layer.start, Math.max(layer.end-layer.start,0))" @mouseleave="clearHighlight">{{ layer.layer_label || layer.layer_name }}</div><div class="field" v-for="f in layer.fields" :key="`${layer.layer_name}-${f.name}-${f.offset}`" @mouseover="highlightField(f.offset,f.length)" @mouseleave="clearHighlight"><span>{{ f.label || f.name }}</span><span :title="f.readable_value">{{ f.readable_value }}</span></div></div></div></div>
              <div class="hex-pane"><div class="sub">Hex</div><div class="hex-box"><div class="hex-row" v-for="(row,rowIndex) in hexRows" :key="rowIndex"><span class="offset">{{ (rowIndex*16).toString(16).padStart(4,'0') }}</span><span v-for="(b,i) in row" :key="`${rowIndex}-${i}`" class="byte" :class="{active:isHighlighted(rowIndex*16+i)}">{{ b.toUpperCase() }}</span></div></div></div>
            </div>
          </div>
        </div>
      </section>
    </main>

    <section class="terminal-center" v-show="terminalVisible">
      <div class="terminal-header"><b>终端中心</b><span><button @click="refreshTerminals">刷新</button><button class="danger" @click="terminalVisible=false">关闭</button></span></div>
      <div class="terminal-layout">
        <aside class="terminal-side">
          <div class="card"><b>本地终端</b><input v-model="localTerminalName" placeholder="名称(可选)"/><button @click="createLocalTerminal">创建</button></div>
          <div class="card"><b>SSH终端</b><input v-model="sshHost" placeholder="Host"/><input v-model.number="sshPort" type="number" placeholder="Port"/><input v-model="sshUser" placeholder="User"/><select v-model="sshAuthMode"><option value="password">密码认证</option><option value="rsa">RSA密钥认证</option></select><input v-if="sshAuthMode==='password'" v-model="sshPass" type="password" placeholder="Password"/><input v-if="sshAuthMode==='rsa'" v-model="sshKeyPath" placeholder="Private Key Path"/><input v-if="sshAuthMode==='rsa'" v-model="sshKeyPassphrase" type="password" placeholder="Key Passphrase(可选)"/><input v-model="sshName" placeholder="显示名(可选)"/><button @click="createSshTerminal">连接SSH</button><div class="hint">长连接 shell：支持二次输入</div></div>
          <div class="term-list"><div v-for="t in terminals" :key="t.id" class="term-item" :class="{active:t.id===activeTerminalId}" @click="activeTerminalId=t.id"><span>{{ t.name }}</span><small>{{ t.connected ? 'online' : 'offline' }}</small></div></div>
        </aside>
        <section class="terminal-main">
          <div class="terminal-main-head"><b>{{ activeTerminal?.name || '未选择终端' }}</b><span><small>用户: {{ terminalUser.username || '-' }} / 角色: {{ terminalUser.role || '-' }}</small><button @click="copyActiveTerminalText">复制输出</button><button class="danger" @click="closeActiveTerminal" :disabled="activeTerminalId==='local-default'">关闭终端</button></span></div>
          <div class="term-banner" v-if="activeTerminalDisconnected">终端连接已断开。<button @click="reconnectActiveTerminal">一键重连</button></div>
          <div class="terminal-shell" @click="terminalEmulator?.focus()"><div ref="terminalHostRef" class="terminal-xterm"></div></div>
        </section>
      </div>
    </section>
  </div>
</template>

<style>
*{box-sizing:border-box;margin:0;padding:0} html,body,#app{width:100%;height:100%} body{font-family:"Segoe UI","Microsoft YaHei",sans-serif;background:#edf3ef;overflow:hidden}
.app{height:100dvh;display:flex;flex-direction:column}.header{height:58px;display:flex;align-items:center;gap:8px;padding:8px 12px;background:#1d5a33;color:#fff}.title{font-weight:700;cursor:pointer}.toolbar{display:flex;gap:6px;flex-wrap:wrap}.flags{margin-left:auto;font-size:13px}.dot{width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:4px}.dot.on{background:#7fff9f}.dot.off{background:#ff7f7f}
button{border:1px solid #2b7244;background:#2f7d4a;color:#fff;border-radius:6px;padding:5px 9px;cursor:pointer} button.danger{background:#fff3f3;color:#9c2a2a;border-color:#e0b5b5} input,select{border:1px solid #c8d6cd;border-radius:6px;padding:6px 8px}
.layout{flex:1;min-height:0;display:grid;grid-template-columns:minmax(320px,370px) minmax(0,1fr);gap:10px;padding:10px}.sidebar,.main-panel{min-height:0;border:1px solid #d2ddd7;border-radius:8px;background:#fff;overflow:hidden}.sidebar{display:grid;grid-template-rows:auto auto minmax(180px,220px) minmax(0,1fr);gap:8px;padding:8px}.card{border:1px solid #dce6e0;border-radius:8px;padding:8px;background:#f9fcfa;min-height:0}.hint{font-size:12px;color:#4d6154}.truncate{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.row{display:grid;grid-template-columns:1fr auto;gap:8px}.grid4{display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px}.mini{font-size:12px;line-height:1.4}.alerts{overflow:auto}.alert{border:1px solid #d5e2d9;border-left:4px solid #b8860b;border-radius:6px;padding:6px;margin-bottom:8px;font-size:12px}.alert[data-level="high"]{border-left-color:#b22222}.alert-head{display:flex;justify-content:space-between;gap:8px;align-items:center}.evidence{margin-top:6px;border-top:1px dashed #cddccf;padding-top:6px}
.main-panel{display:grid;grid-template-rows:auto auto 1fr}.panel-top{display:flex;align-items:center;gap:8px;padding:8px;border-bottom:1px solid #d7e1da;flex-wrap:wrap}.current-file{margin-left:auto;font-size:12px;max-width:44%;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.error{color:#9a1e1e;font-size:12px;padding:6px 8px}.main-grid{min-height:0;display:grid;grid-template-columns:minmax(380px,44%) minmax(0,56%)}.list-area,.detail-area{min-height:0}.list-area{border-right:1px solid #e3ebe5;display:grid;grid-template-rows:auto 1fr}.file-panel{max-height:200px;overflow:auto;padding:6px}.table-wrap{min-height:0;overflow:auto} table{width:max-content;min-width:100%;border-collapse:collapse;table-layout:auto;font-size:13px} th,td{border-bottom:1px solid #e8efe9;padding:7px 8px;white-space:nowrap} thead{position:sticky;top:0;background:#2a6c42;color:#fff} tr.selected{background:#ddefe2}
.detail-grid{height:100%;display:grid;grid-template-columns:minmax(360px,1fr) minmax(280px,1fr)}.parse-pane,.hex-pane{min-height:0;display:grid;grid-template-rows:auto 1fr;padding:8px}.sub{font-weight:700;margin-bottom:6px}.parse-scroll,.hex-box{min-height:0;overflow:auto}.layer{border:1px solid #dce6df;border-radius:6px;margin-bottom:8px}.layer-head{background:#e9f3ec;padding:6px;font-weight:700;font-size:12px}.field{padding:6px;border-top:1px dashed #dbe5de;display:grid;grid-template-columns:34% 66%;gap:6px;font-size:12px}
.hex-row{display:flex;gap:6px;margin-bottom:4px;font-family:Consolas,monospace;font-size:12px}.offset{width:44px;color:#5f7266}.byte{min-width:22px;text-align:center;border-radius:4px;padding:2px 0}.byte.active{background:#ffe28f;color:#5b3b00;font-weight:700}
.terminal-center{position:fixed;left:12px;right:12px;top:72px;bottom:12px;border:1px solid #c7d9ce;border-radius:10px;background:#f7fbf8;z-index:90;display:grid;grid-template-rows:auto 1fr}.terminal-header{padding:10px;border-bottom:1px solid #dbe7df;display:flex;justify-content:space-between;align-items:center}.terminal-layout{min-height:0;display:grid;grid-template-columns:320px minmax(0,1fr)}.terminal-side{border-right:1px solid #dce8e0;padding:10px;overflow:auto}.term-list{display:grid;gap:6px}.term-item{border:1px solid #d4e1d8;border-radius:6px;padding:6px;display:flex;justify-content:space-between;cursor:pointer}.term-item.active{border-color:#2f7d4a;background:#e9f4ed}.terminal-main{min-height:0;display:flex;flex-direction:column}.terminal-main-head{padding:10px;border-bottom:1px solid #e0ebe4;display:flex;justify-content:space-between;gap:8px}.term-banner{padding:8px 10px;background:#fff8dd;border-bottom:1px solid #f0e2a3;color:#735b00;display:flex;gap:10px;align-items:center}.terminal-shell{min-height:0;flex:1;background:#132a1d;padding:8px}.terminal-xterm{width:100%;height:100%}
@media (max-width:980px){.layout{grid-template-columns:1fr}.sidebar{max-height:45dvh;overflow:auto}.main-grid{grid-template-columns:1fr}.terminal-layout{grid-template-columns:1fr;grid-template-rows:auto 1fr}}
</style>
