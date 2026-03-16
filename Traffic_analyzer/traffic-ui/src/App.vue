<script setup>
import { ref, onMounted } from "vue"

const packets = ref([])

async function loadPackets() {
  try {
    const res = await fetch("http://127.0.0.1:8000/packets")
    packets.value = await res.json()
  } catch (error) {
    console.error("加载失败:", error)
  }
}

onMounted(() => {
  loadPackets()
})
</script>

<template>
  <div class="app">
    
    <header class="header">
      <div class="title">PCAP Packet Analyzer</div>
      <div class="toolbar">
        <button>开始抓包</button>
        <button>停止抓包</button>
        <button>导入PCAP</button>
      </div>
    </header>

    <main class="content">
      <table class="packet-table">
        <thead>
          <tr>
            <th style="width: 60px;">No</th>
            <th>Ether</th>
            <th>From</th>
            <th>To</th>
            <th style="width: 100px;">Length</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="p in packets" :key="p.id">
            <td>{{ p.id }}</td>
            <td>{{ p.summary.split("Ether / ")[1]?.split(" ")[0] || '-' }}</td>
            <td>{{ p.summary.split("says ")[1]?.split(" ")[0] || '-' }}</td>
            <td>{{ p.summary.split("who has ")[1]?.split(" ")[0] || '-' }}</td>
            <td>{{ p.length }}</td>
          </tr>
        </tbody>
      </table>
    </main>

  </div>
</template>

<style>

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

html, body {
  width: 100%;
  height: 100%;
}
/* 基础重置 */
body {
  background-image: url("./assets/bgp.jpg");
  background-size: cover;
  margin: 0;
  font-family: Arial, sans-serif;
  overflow: hidden; /* 禁止全局滚动条，由 .content 接管 */
}

/* 布局核心 */
.app {
  height: 100vh;
  display: flex;
  flex-direction: column;
}

.header {
  height: 60px;
  display: flex;
  align-items: center;
  background: #083008;
  color: white;
  padding: 0 20px;
  /* 标题栏高度永不缩小 */
  flex-shrink: 0; 
  z-index: 10;
}

.title {
  font-size: 20px;
  /* line-height: 60px; */
  font-weight: bold;
  white-space: nowrap;
}

.toolbar {
  margin-left: 30px;
  display: flex;
  gap: 10px;
}

/* 核心滚动区域 */
.content {
  flex: 1; /* 自动撑开占据剩余所有空间 */
  padding: 20px;
  overflow: auto; /* 只有这个区域会出现滚动条 */
  background-color: rgba(255, 255, 255, 0.6);
}

/* 表格样式优化 */
.packet-table {
  width: 100%;
  min-width: 800px; /* 保证最窄不会挤成一团 */
  border-collapse: collapse;
  background-color: rgba(249, 254, 248, 0.714);
  table-layout: fixed; /* 固定布局，防止单元格被内容撑得忽大忽小 */
  box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}

.packet-table th {
  background: #145214;
  border: 1px solid rgb(255, 255, 255);
  color: white;
  padding: 12px 10px;
  text-align: left;
  position: sticky; /* 关键：表头吸顶 */
  top: 0;          
  z-index: 2;
}

.packet-table td {
  padding: 10px;
  border: 1px solid white;
  font-family: 'Courier New', Courier, monospace; /* 适合查看协议数据 */
  font-size: 14px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis; /* 超出部分显示省略号 */
}

.packet-table tr:hover {
  background: #f0fff0;
}

button {
  padding: 6px 12px;
  cursor: pointer;
  background: #1e631e;
  border: 1px solid #2a7a2a;
  color: white;
  border-radius: 4px;
}

button:hover {
  background: #2a7a2a;
}
</style>