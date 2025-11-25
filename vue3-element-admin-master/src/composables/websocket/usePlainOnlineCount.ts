import { ref } from "vue";
import { AuthStorage } from "@/utils/auth";

interface PlainOnlineCountOptions {
  reconnectInterval?: number; // 重连间隔(ms)
  pingInterval?: number; // 主动 ping 间隔(ms)
  endpoint?: string; // 自定义端点，默认取环境变量
  debug?: boolean;
}

export function usePlainOnlineCount(options: PlainOnlineCountOptions = {}) {
  const envPing = Number(import.meta.env.VITE_APP_WS_PING_INTERVAL) || 0;
  const reconnectInterval = options.reconnectInterval ?? 15000;
  const pingInterval = options.pingInterval ?? (envPing > 0 ? envPing : 30000);
  const endpoint = options.endpoint || import.meta.env.VITE_APP_WS_ENDPOINT;
  const onlineUserCount = ref(0);
  const lastUpdateTime = ref<number>(0);
  const isConnected = ref(false);
  const isConnecting = ref(false);

  let ws: WebSocket | null = null;
  let reconnectTimer: any = null;
  let pingTimer: any = null;

  const initWebSocket = () => {
    if (!endpoint) {
      return;
    }
    if (isConnecting.value || isConnected.value) {
      return;
    }
    const token = AuthStorage.getAccessToken();
    if (!token) {
      return;
    }

    // 附加 token 作为查询参数（示例，不安全场景需后端校验）
    let url = endpoint;
    url += endpoint.includes("?")
      ? `&token=${encodeURIComponent(token)}`
      : `?token=${encodeURIComponent(token)}`;

    isConnecting.value = true;
    ws = new WebSocket(url);

    ws.onopen = () => {
      isConnecting.value = false;
      isConnected.value = true;
      startPing();
    };

    ws.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        // 支持 {count, users, timestamp}
        const count = typeof data === "number" ? data : data.count;
        if (!isNaN(count)) {
          onlineUserCount.value = count;
          lastUpdateTime.value = Date.now();
        }
        // 已精简：不再解析用户列表
      } catch (e) {
        // 解析失败时记录以便排查消息格式问题
        console.warn(e);
      }
    };

    ws.onerror = () => {
      // error event
    };

    ws.onclose = () => {
      // closed, will reconnect
      cleanupSocket(false);
      scheduleReconnect();
    };
  };

  function scheduleReconnect() {
    if (reconnectTimer) clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(() => {
      if (!isConnected.value) initWebSocket();
    }, reconnectInterval);
  }

  function startPing() {
    if (pingTimer) clearInterval(pingTimer);
    // 主动发送 ping 请求在线人数（服务端解析 action=ping 立即返回）
    pingTimer = setInterval(() => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ action: "ping" }));
      }
    }, pingInterval);
  }

  function cleanupSocket(markDisconnected = true) {
    if (pingTimer) {
      clearInterval(pingTimer);
      pingTimer = null;
    }
    if (ws) {
      try {
        ws.close();
      } catch (err) {
        console.warn(err);
      }
    }
    ws = null;
    if (markDisconnected) {
      isConnected.value = false;
      isConnecting.value = false;
    }
  }

  const closeWebSocket = () => {
    cleanupSocket();
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
  };

  return {
    onlineUserCount,
    lastUpdateTime,
    isConnected,
    isConnecting,
    initWebSocket,
    closeWebSocket,
  };
}
