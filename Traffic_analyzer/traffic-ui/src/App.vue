
<script setup>
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from "vue";

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
const terminalLogs = ref([]);
const terminalInput = ref("");
const terminalLogRef = ref(null);
const sshHost = ref("");
const sshPort = ref(22);
const sshUser = ref("");
const sshPass = ref("");
const sshName = ref("");
const localTerminalName = ref("");

const captureInterfaces = ref([]);
const selectedCaptureIfaceIndex = ref(-1);
const loadingIfaces = ref(false);
const hasDesktopBridge = computed(() => Boolean(window?.go?.main?.App));

const hexBytes = computed(() => (detail.value?.raw_hex?.match(/.{1,2}/g) || []));
const hexRows = computed(() => {
  const rows = [];
  for (let i = 0; i < hexBytes.value.length; i += 16) rows.push(hexBytes.value.slice(i, i + 16));
  return rows;
});
const liveFiles = computed(() => fileItems.value.filter((f) => f.relative_path.toLowerCase().startsWith("live/")).sort((a, b) => a.modified_at - b.modified_at));
const activeTerminal = computed(() => terminals.value.find((t) => t.id === activeTerminalId.value));
const selectedIfaceLabel = computed(() => captureInterfaces.value.find((i) => i.index === Number(selectedCaptureIfaceIndex.value))?.display || "自动选择");

async function callApp(method, ...args) {
  if (!hasDesktopBridge.value) throw new Error("当前为 Web 模式，桌面桥接不可用");
  const fn = window?.go?.main?.App?.[method];
  if (!fn) throw new Error(`Wails binding missing: ${method}`);
  return fn(...args);
}

function clearHighlight() { highlightStart.value = -1; highlightLength.value = 0; }
function highlightField(offset, length) { highlightStart.value = offset; highlightLength.value = length; }
function isHighlighted(i) { return highlightStart.value >= 0 && highlightLength.value > 0 && i >= highlightStart.value && i < highlightStart.value + highlightLength.value; }
function toggleTitleMenu() { titleMenuOpen.value = !titleMenuOpen.value; }
async function toggleTerminal() { terminalVisible.value = !terminalVisible.value; titleMenuOpen.value = false; if (terminalVisible.value) { await refreshTerminals(); await refreshTerminalLogs(); } }

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
  if (!hasDesktopBridge.value) {
    captureInterfaces.value = [];
    return;
  }
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

async function refreshServiceStatus() { if (!hasDesktopBridge.value) return; try { serviceStatus.value = await callApp("ServiceStatus"); } catch (e) { actionMessage.value = `状态获取失败: ${e}`; } }
async function startEmbeddedStack() { if (!hasDesktopBridge.value) { actionMessage.value = "Web 模式无需内置启动，请使用脚本启动后端/抓包"; return; } try { serviceStatus.value = { ...serviceStatus.value, ...(await callApp("StartEmbeddedStack")) }; } catch (e) { actionMessage.value = `启动失败: ${e}`; } }
async function stopEmbeddedStack() { if (!hasDesktopBridge.value) return; try { serviceStatus.value = await callApp("StopEmbeddedStack"); } catch (e) { actionMessage.value = `停止失败: ${e}`; } }
async function startCapture() {
  if (!hasDesktopBridge.value) { actionMessage.value = "Web 模式请通过 scripts/start_go_capture.ps1 启动抓包"; return; }
  try {
    const idx = Number(selectedCaptureIfaceIndex.value);
    if (Number.isInteger(idx) && idx >= 0) await callApp("StartCaptureWithInterface", idx, "");
    else await callApp("StartCapture");
    await refreshServiceStatus();
    actionMessage.value = `抓包启动: ${selectedIfaceLabel.value}`;
  } catch (e) { actionMessage.value = `抓包启动失败: ${e}`; }
}
async function stopCapture() { if (!hasDesktopBridge.value) return; try { await callApp("StopCapture"); await refreshServiceStatus(); } catch (e) { actionMessage.value = `抓包停止失败: ${e}`; } }

async function refreshAnalysis() { try { const r = await fetch(`${API_BASE}/analysis/report`); if (!r.ok) throw new Error(`HTTP ${r.status}`); report.value = await r.json(); } catch (e) { actionMessage.value = `检测刷新失败: ${e}`; } }
async function refreshFileCatalog(s = false) { if (!s) fileError.value = ""; try { const r = await fetch(`${API_BASE}/pcap-files`); if (!r.ok) throw new Error(`HTTP ${r.status}`); const d = await r.json(); fileItems.value = d.items || []; currentFile.value = d.current_file || ""; } catch (e) { fileError.value = `加载文件列表失败: ${e}`; } }
async function loadPackets() {
  listError.value = "";
  try {
    const r = await fetch(`${API_BASE}/packets?offset=0&limit=1000`); if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const d = await r.json(); packets.value = d.items || []; total.value = d.total || packets.value.length;
    if (!packets.value.length) { selectedPacketId.value = null; detail.value = null; return; }
    if (!packets.value.some((p) => p.id === selectedPacketId.value)) await selectPacket(packets.value[0].id);
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
  if (!hasDesktopBridge.value) return;
  try {
    terminals.value = await callApp("ListTerminals");
    if (!terminals.value.find((t) => t.id === activeTerminalId.value) && terminals.value.length) activeTerminalId.value = terminals.value[0].id;
  } catch (e) { actionMessage.value = `终端列表获取失败: ${e}`; }
}

async function refreshTerminalLogs() {
  if (!hasDesktopBridge.value) return;
  if (!activeTerminalId.value) return;
  try {
    terminalLogs.value = await callApp("GetTerminalLogsByID", activeTerminalId.value, 600);
    await nextTick(); if (terminalLogRef.value) terminalLogRef.value.scrollTop = terminalLogRef.value.scrollHeight;
  } catch (e) { actionMessage.value = `终端日志获取失败: ${e}`; }
}

async function createLocalTerminal() { if (!hasDesktopBridge.value) return; try { const i = await callApp("CreateLocalTerminal", localTerminalName.value.trim()); localTerminalName.value = ""; await refreshTerminals(); activeTerminalId.value = i.id; } catch (e) { actionMessage.value = `创建本地终端失败: ${e}`; } }
async function createSshTerminal() {
  if (!hasDesktopBridge.value) return;
  try {
    const i = await callApp("CreateSSHTerminal", sshHost.value.trim(), Number(sshPort.value || 22), sshUser.value.trim(), sshPass.value, sshName.value.trim());
    sshPass.value = ""; await refreshTerminals(); activeTerminalId.value = i.id;
  } catch (e) { actionMessage.value = `创建SSH终端失败: ${e}`; }
}
async function closeActiveTerminal() { if (!hasDesktopBridge.value || !activeTerminalId.value || activeTerminalId.value === "local-default") return; await callApp("CloseTerminal", activeTerminalId.value); await refreshTerminals(); }
async function clearActiveTerminalLogs() { if (!hasDesktopBridge.value || !activeTerminalId.value) return; await callApp("ClearTerminalLogsByID", activeTerminalId.value); terminalLogs.value = []; }
async function executeTerminalCommand() {
  if (!hasDesktopBridge.value) return;
  const cmd = terminalInput.value;
  if (!cmd.trim() || !activeTerminalId.value) return;
  terminalInput.value = "";
  const result = await callApp("ExecuteTerminalCommandByID", activeTerminalId.value, cmd);
  actionMessage.value = `终端状态: ${result}`;
  setTimeout(() => refreshTerminalLogs(), 120);
}

async function pollingTick() {
  if (autoRefreshFiles.value) await refreshFileCatalog(true);
  if (autoParseLive.value && !actionRunning) { const next = nextUnparsedLiveFile(); if (next) await loadDataFile(next.relative_path, { silent: true }); }
  await refreshServiceStatus(); await refreshAnalysis(); if (terminalVisible.value) await refreshTerminalLogs();
}

function startPolling() { stopPolling(); pollTimer = setInterval(() => { pollingTick(); }, POLL_INTERVAL_MS); }
function stopPolling() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }

async function init() {
  if (hasDesktopBridge.value) {
    await startEmbeddedStack();
    await refreshCaptureInterfaces();
    await refreshServiceStatus();
    await refreshTerminals();
    await refreshTerminalLogs();
  } else {
    actionMessage.value = "Web 模式: 已启用分析面板，终端与网卡控制仅桌面版可用";
  }
  await refreshFileCatalog();
  await loadPackets();
  await refreshAnalysis();
  startPolling();
}

watch(activeTerminalId, () => refreshTerminalLogs());
onMounted(async () => { await init(); });
onUnmounted(() => stopPolling());
</script>

<template>
  <div class="app">
    <header class="header">
      <div class="title" @click="toggleTitleMenu">Traffic Analyzer Desktop</div>
      <div class="title-menu" v-if="titleMenuOpen"><button @click="toggleTerminal" :disabled="!hasDesktopBridge">终端中心</button></div>
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
          <div class="row"><select v-model.number="selectedCaptureIfaceIndex" :disabled="!hasDesktopBridge"><option :value="-1">自动选择</option><option v-for="i in captureInterfaces" :key="i.index" :value="i.index">{{ i.display }}</option></select><button @click="refreshCaptureInterfaces" :disabled="loadingIfaces || !hasDesktopBridge">刷新</button></div>
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
              <div class="parse-pane"><div class="sub">解析数据</div><div class="parse-scroll"><div class="layer" v-for="layer in detail.layers" :key="`${layer.layer_name}-${layer.start}`"><div class="layer-head" @mouseover="highlightField(layer.start, Math.max(layer.end-layer.start,0))" @mouseleave="clearHighlight">{{ layer.layer_label || layer.layer_name }} [{{ layer.start }}-{{ layer.end }}]</div><div class="field" v-for="f in layer.fields" :key="`${layer.layer_name}-${f.name}-${f.offset}`" @mouseover="highlightField(f.offset,f.length)" @mouseleave="clearHighlight"><span>{{ f.label || f.name }}</span><span :title="f.readable_value">{{ f.readable_value }}</span><span :title="f.value">原始: {{ f.value }}</span></div></div></div></div>
              <div class="hex-pane"><div class="sub">Hex</div><div class="hex-box"><div class="hex-row" v-for="(row,rowIndex) in hexRows" :key="rowIndex"><span class="offset">{{ (rowIndex*16).toString(16).padStart(4,'0') }}</span><span v-for="(b,i) in row" :key="`${rowIndex}-${i}`" class="byte" :class="{active:isHighlighted(rowIndex*16+i)}">{{ b.toUpperCase() }}</span></div></div></div>
            </div>
          </div>
        </div>
      </section>
    </main>

    <section class="terminal-center" v-if="terminalVisible && hasDesktopBridge">
      <div class="terminal-header"><b>终端中心</b><span><button @click="refreshTerminals">刷新</button><button class="danger" @click="terminalVisible=false">关闭</button></span></div>
      <div class="terminal-layout">
        <aside class="terminal-side">
          <div class="card"><b>本地终端</b><input v-model="localTerminalName" placeholder="名称(可选)"/><button @click="createLocalTerminal">创建</button></div>
          <div class="card"><b>SSH终端</b><input v-model="sshHost" placeholder="Host"/><input v-model.number="sshPort" type="number" placeholder="Port"/><input v-model="sshUser" placeholder="User"/><input v-model="sshPass" type="password" placeholder="Password"/><input v-model="sshName" placeholder="显示名(可选)"/><button @click="createSshTerminal">连接SSH</button><div class="hint">长连接 shell：支持二次输入</div></div>
          <div class="term-list"><div v-for="t in terminals" :key="t.id" class="term-item" :class="{active:t.id===activeTerminalId}" @click="activeTerminalId=t.id"><span>{{ t.name }}</span><small>{{ t.connected ? 'online' : 'offline' }}</small></div></div>
        </aside>
        <section class="terminal-main">
          <div class="terminal-main-head"><b>{{ activeTerminal?.name || '未选择终端' }}</b><span><button @click="refreshTerminalLogs">刷新日志</button><button @click="clearActiveTerminalLogs">清空日志</button><button class="danger" @click="closeActiveTerminal" :disabled="activeTerminalId==='local-default'">关闭终端</button></span></div>
          <div class="terminal-console" ref="terminalLogRef"><div class="line" v-for="(line,idx) in terminalLogs" :key="idx">[{{ line.timestamp }}][{{ line.source }}] {{ line.line }}</div><div class="prompt-row"><span>{{ activeTerminal?.type==='ssh' ? 'ssh>' : 'local>' }}</span><input class="prompt-input" v-model="terminalInput" @keyup.enter="executeTerminalCommand" placeholder="直接输入命令并回车执行"/></div></div>
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
.main-panel{display:grid;grid-template-rows:auto auto 1fr}.panel-top{display:flex;align-items:center;gap:8px;padding:8px;border-bottom:1px solid #d7e1da;flex-wrap:wrap}.current-file{margin-left:auto;font-size:12px;max-width:44%;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.error{color:#9a1e1e;font-size:12px;padding:6px 8px}.main-grid{min-height:0;display:grid;grid-template-columns:minmax(380px,44%) minmax(0,56%)}.list-area,.detail-area{min-height:0}.list-area{border-right:1px solid #e3ebe5;display:grid;grid-template-rows:auto 1fr}.file-panel{max-height:200px;overflow:auto;padding:6px}.table-wrap{min-height:0;overflow:auto} table{width:100%;border-collapse:collapse;table-layout:fixed;font-size:13px} th,td{border-bottom:1px solid #e8efe9;padding:7px 8px;text-overflow:ellipsis;overflow:hidden;white-space:nowrap} thead{position:sticky;top:0;background:#2a6c42;color:#fff} tr.selected{background:#ddefe2}
.detail-grid{height:100%;display:grid;grid-template-columns:minmax(360px,1fr) minmax(280px,1fr)}.parse-pane,.hex-pane{min-height:0;display:grid;grid-template-rows:auto 1fr;padding:8px}.sub{font-weight:700;margin-bottom:6px}.parse-scroll,.hex-box{min-height:0;overflow:auto}.layer{border:1px solid #dce6df;border-radius:6px;margin-bottom:8px}.layer-head{background:#e9f3ec;padding:6px;font-weight:700;font-size:12px}.field{padding:6px;border-top:1px dashed #dbe5de;display:grid;grid-template-columns:24% 38% 38%;gap:6px;font-size:12px}
.hex-row{display:flex;gap:6px;margin-bottom:4px;font-family:Consolas,monospace;font-size:12px}.offset{width:44px;color:#5f7266}.byte{min-width:22px;text-align:center;border-radius:4px;padding:2px 0}.byte.active{background:#ffe28f;color:#5b3b00;font-weight:700}
.terminal-center{position:fixed;left:12px;right:12px;top:72px;bottom:12px;border:1px solid #c7d9ce;border-radius:10px;background:#f7fbf8;z-index:90;display:grid;grid-template-rows:auto 1fr}.terminal-header{padding:10px;border-bottom:1px solid #dbe7df;display:flex;justify-content:space-between;align-items:center}.terminal-layout{min-height:0;display:grid;grid-template-columns:320px minmax(0,1fr)}.terminal-side{border-right:1px solid #dce8e0;padding:10px;overflow:auto}.term-list{display:grid;gap:6px}.term-item{border:1px solid #d4e1d8;border-radius:6px;padding:6px;display:flex;justify-content:space-between;cursor:pointer}.term-item.active{border-color:#2f7d4a;background:#e9f4ed}.terminal-main{min-height:0;display:grid;grid-template-rows:auto 1fr}.terminal-main-head{padding:10px;border-bottom:1px solid #e0ebe4;display:flex;justify-content:space-between;gap:8px}.terminal-console{min-height:0;overflow:auto;padding:10px;background:#132a1d;color:#cde6d6;font-family:Consolas,monospace;font-size:12px;white-space:pre-wrap}.line{margin-bottom:4px}.prompt-row{display:grid;grid-template-columns:auto 1fr;gap:8px;align-items:center;border-top:1px solid #2a4a38;margin-top:8px;padding-top:8px;position:sticky;bottom:0;background:#132a1d}.prompt-input{background:transparent;border:none;outline:none;color:#d9f7e5;font-family:inherit}
@media (max-width:980px){.layout{grid-template-columns:1fr}.sidebar{max-height:45dvh;overflow:auto}.main-grid{grid-template-columns:1fr}.terminal-layout{grid-template-columns:1fr;grid-template-rows:auto 1fr}}
</style>
