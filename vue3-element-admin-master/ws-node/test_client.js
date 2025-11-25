const WebSocket = require("ws");
const Redis = require("ioredis");

const WS_URL = process.env.WS_URL || "ws://localhost:8989";
const REDIS_HOST = process.env.REDIS_HOST || "192.168.0.28";
const REDIS_PORT = process.env.REDIS_PORT || 6379;
const REDIS_PASSWORD = process.env.REDIS_PASSWORD || "redis_a82mHW";
const CHANNEL = process.env.REDIS_CHANNEL || "online_count";

console.log("[test_client] 尝试连接 WebSocket:", WS_URL);
const ws = new WebSocket(WS_URL);

ws.on("open", () => {
  console.log("[test_client] WebSocket 已连接");
  // 连接成功后发布一条测试消息到 Redis
  const pub = new Redis({ host: REDIS_HOST, port: REDIS_PORT, password: REDIS_PASSWORD });
  const msg = JSON.stringify({ count: Math.floor(Math.random() * 100) + 1, timestamp: Date.now() });
  pub
    .publish(CHANNEL, msg)
    .then(() => {
      console.log("[test_client] 已向 Redis 频道发布测试消息:", CHANNEL, msg);
      pub.disconnect();
    })
    .catch((err) => {
      console.error("[test_client] 发布到 Redis 失败:", err);
      pub.disconnect();
    });
});

ws.on("message", (data) => {
  console.log("[test_client] 收到消息：", data.toString());
  // 退出进程
  setTimeout(() => process.exit(0), 500);
});

ws.on("error", (err) => {
  console.error("[test_client] WebSocket 错误:", err.message || err);
  process.exit(2);
});

ws.on("close", (code, reason) => {
  console.log("[test_client] WebSocket 关闭:", code, reason?.toString());
});
