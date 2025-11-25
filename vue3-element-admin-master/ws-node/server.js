// Node.js WebSocket 服务，支持 Redis 后端推送
require("dotenv").config();
const WebSocket = require("ws");
const Redis = require("ioredis");

const PORT = process.env.PORT || 9000;
const REDIS_HOST = process.env.REDIS_HOST || "127.0.0.1";
const REDIS_PORT = process.env.REDIS_PORT || 6379;
const REDIS_PASSWORD = process.env.REDIS_PASSWORD || "";
const REDIS_CHANNEL = process.env.REDIS_CHANNEL || "online_count";

const wss = new WebSocket.Server({ port: PORT });
const redis = new Redis({
  host: REDIS_HOST,
  port: REDIS_PORT,
  password: REDIS_PASSWORD,
});

console.log(`[ws-node] WebSocket 服务启动于端口 ${PORT}`);
console.log(`[ws-node] Redis 连接: ${REDIS_HOST}:${REDIS_PORT}`);

// 订阅 Redis online_count 频道
redis.subscribe(REDIS_CHANNEL, (err, count) => {
  if (err) {
    console.error("Redis 订阅失败:", err);
  } else {
    console.log(`已订阅 Redis 频道: ${REDIS_CHANNEL}`);
  }
});

redis.on("message", (channel, message) => {
  if (channel === REDIS_CHANNEL) {
    // 广播给所有连接的客户端，并打印当前在线数
    console.log(`[ws-node] 广播 Redis 消息到 ${wss.clients.size} 个客户端: ${message}`);
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        try {
          client.send(message);
        } catch (err) {
          console.error("[ws-node] 广播消息失败:", err);
        }
      }
    });
  }
});

wss.on("connection", (ws, req) => {
  console.log("WebSocket 客户端已连接:", req.socket.remoteAddress, "当前连接数:", wss.clients.size);

  // 给新连接的客户端发送当前在线数作为初始值
  try {
    const initMsg = JSON.stringify({ count: wss.clients.size, timestamp: Date.now() });
    ws.send(initMsg);
  } catch (err) {
    console.warn("[ws-node] 发送初始在线数失败:", err);
  }

  // 广播给所有客户端当前在线数（包括新连接）
  try {
    const bc = JSON.stringify({ count: wss.clients.size, timestamp: Date.now() });
    console.log("[ws-node] 广播连接变更在线数:", bc);
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(bc);
      }
    });
  } catch (err) {
    console.warn("[ws-node] 广播连接变更失败:", err);
  }

  ws.on("message", (data) => {
    // 解析客户端消息，支持 { action: 'ping' }
    try {
      const msg = typeof data === "string" ? data : data.toString();
      const obj = JSON.parse(msg);
      if (obj && obj.action === "ping") {
        // 回复当前在线人数给发起 ping 的客户端
        const reply = JSON.stringify({ count: wss.clients.size, timestamp: Date.now() });
        ws.send(reply);
      }
    } catch (err) {
      // 非 JSON 或其他消息，忽略
    }
  });

  ws.on("close", () => {
    console.log("WebSocket 客户端断开:", req.socket.remoteAddress, "当前连接数:", wss.clients.size);
    // 广播断开后最新在线数
    try {
      const bc = JSON.stringify({ count: wss.clients.size, timestamp: Date.now() });
      console.log("[ws-node] 广播断开后在线数:", bc);
      wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(bc);
        }
      });
    } catch (err) {
      console.warn("[ws-node] 广播断开变更失败:", err);
    }
  });
});
