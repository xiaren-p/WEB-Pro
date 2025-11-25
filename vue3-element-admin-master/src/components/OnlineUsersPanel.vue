<template>
  <el-card class="online-users-panel" shadow="hover">
    <div class="flex-x-between flex-y-center">
      <div>
        <el-icon v-if="isConnected" color="#67C23A"><CircleCheck /></el-icon>
        <el-icon v-else color="#F56C6C"><CircleClose /></el-icon>
        <span class="ml-2">WebSocket连接状态：</span>
        <span :style="{ color: isConnected ? '#67C23A' : '#F56C6C' }">
          {{ isConnected ? "已连接" : "断开" }}
        </span>
      </div>
      <div>
        <el-icon><UserFilled /></el-icon>
        <span class="ml-2">当前在线人数：</span>
        <span class="font-bold text-lg">{{ onlineUserCount }}</span>
      </div>
    </div>
  </el-card>
</template>

<script setup lang="ts">
import { onMounted, onBeforeUnmount } from "vue";
import { usePlainOnlineCount } from "@/composables/websocket/usePlainOnlineCount";
import { CircleCheck, CircleClose, UserFilled } from "@element-plus/icons-vue";

const { onlineUserCount, isConnected, initWebSocket, closeWebSocket } = usePlainOnlineCount();

onMounted(() => {
  initWebSocket();
});

onBeforeUnmount(() => {
  closeWebSocket();
});
</script>

<style scoped>
.online-users-panel {
  margin-bottom: 16px;
  padding: 12px 20px;
}
.font-bold {
  font-weight: bold;
}
.text-lg {
  font-size: 1.2em;
}
</style>
