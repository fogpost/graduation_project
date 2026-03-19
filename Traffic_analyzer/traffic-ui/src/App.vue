<script setup>
import { ref, onMounted } from "vue";

const packets = ref([]);
const total = ref(0);
const errorMessage = ref("");

async function loadPackets() {
  errorMessage.value = "";
  try {
    const res = await fetch("http://127.0.0.1:8000/packets?offset=0&limit=500");
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    const data = await res.json();
    packets.value = Array.isArray(data) ? data : data.items || [];
    total.value = Array.isArray(data) ? data.length : data.total || packets.value.length;
  } catch (error) {
    errorMessage.value = `加载失败: ${error}`;
    console.error("加载失败:", error);
  }
}

onMounted(() => {
  loadPackets();
});
</script>

<template>
  <div class="app">
    <header class="header">
      <div class="title">PCAP Packet Analyzer</div>
      <div class="toolbar">
        <button @click="loadPackets">刷新列表</button>
      </div>
      <div class="total">总包数: {{ total }}</div>
    </header>

    <main class="content">
      <div v-if="errorMessage" class="error">{{ errorMessage }}</div>
      <table class="packet-table">
        <thead>
          <tr>
            <th style="width: 60px">No</th>
            <th>Ether</th>
            <th>From</th>
            <th>To</th>
            <th style="width: 100px">Length</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="p in packets" :key="p.id">
            <td>{{ p.id }}</td>
            <td>{{ p.summary.split("Ether / ")[1]?.split(" ")[0] || "-" }}</td>
            <td>{{ p.summary.split("says ")[1]?.split(" ")[0] || "-" }}</td>
            <td>{{ p.summary.split("who has ")[1]?.split(" ")[0] || "-" }}</td>
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

html,
body {
  width: 100%;
  height: 100%;
}

body {
  background-image: url("./assets/bgp.jpg");
  background-size: cover;
  margin: 0;
  font-family: Arial, sans-serif;
  overflow: hidden;
}

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
  flex-shrink: 0;
  z-index: 10;
}

.title {
  font-size: 20px;
  font-weight: bold;
  white-space: nowrap;
}

.toolbar {
  margin-left: 30px;
  display: flex;
  gap: 10px;
}

.total {
  margin-left: auto;
}

.content {
  flex: 1;
  padding: 20px;
  overflow: auto;
  background-color: rgba(255, 255, 255, 0.6);
}

.error {
  margin-bottom: 12px;
  color: #8b0000;
  font-weight: 600;
}

.packet-table {
  width: 100%;
  min-width: 800px;
  border-collapse: collapse;
  background-color: rgba(249, 254, 248, 0.714);
  table-layout: fixed;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.packet-table th {
  background: #145214;
  border: 1px solid rgb(255, 255, 255);
  color: white;
  padding: 12px 10px;
  text-align: left;
  position: sticky;
  top: 0;
  z-index: 2;
}

.packet-table td {
  padding: 10px;
  border: 1px solid white;
  font-family: "Courier New", Courier, monospace;
  font-size: 14px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
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
