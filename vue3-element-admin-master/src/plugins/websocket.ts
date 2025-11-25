import { useDictSync } from "@/composables";
import { usePlainOnlineCount } from "@/composables/websocket/usePlainOnlineCount";
import { AuthStorage } from "@/utils/auth";
// 不直接导入 store 或 userStore

// 全局 WebSocket 实例管理
const websocketInstances = new Map<string, any>();

// 用于防止重复初始化的状态标记
let isInitialized = false;
let dictWebSocketInstance: ReturnType<typeof useDictSync> | null = null;

/**
 * 注册 WebSocket 实例
 */
export function registerWebSocketInstance(key: string, instance: any) {
  websocketInstances.set(key, instance);
  console.log(`[WebSocketPlugin] Registered WebSocket instance: ${key}`);
}

/**
 * 获取 WebSocket 实例
 */
export function getWebSocketInstance(key: string) {
  return websocketInstances.get(key);
}

/**
 * 初始化WebSocket服务
 */
export function setupWebSocket() {
  // WebSocket 功能已在回滚中被禁用，setupWebSocket 为 no-op。
  return;
}

/**
 * 处理窗口关闭
 */
function handleWindowClose() {
  console.log("[WebSocketPlugin] 窗口即将关闭，断开WebSocket连接");
  cleanupWebSocket();
}

/**
 * 清理WebSocket连接
 */
export function cleanupWebSocket() {
  // 清理字典 WebSocket
  if (dictWebSocketInstance) {
    try {
      dictWebSocketInstance.closeWebSocket();
      console.log("[WebSocketPlugin] 字典WebSocket连接已断开");
    } catch (error) {
      console.error("[WebSocketPlugin] 断开字典WebSocket连接失败:", error);
    }
  }

  // 清理所有注册的 WebSocket 实例
  websocketInstances.forEach((instance, key) => {
    try {
      if (instance && typeof instance.disconnect === "function") {
        instance.disconnect();
        console.log(`[WebSocketPlugin] ${key} WebSocket连接已断开`);
      } else if (instance && typeof instance.closeWebSocket === "function") {
        instance.closeWebSocket();
        console.log(`[WebSocketPlugin] ${key} WebSocket连接已断开`);
      }
    } catch (error) {
      console.error(`[WebSocketPlugin] 断开 ${key} WebSocket连接失败:`, error);
    }
  });

  // 清空实例映射
  websocketInstances.clear();

  // 移除事件监听器
  window.removeEventListener("beforeunload", handleWindowClose);

  // 重置状态
  dictWebSocketInstance = null;
  isInitialized = false;
}

/**
 * 重新初始化WebSocket（用于登录后重连）
 */
export function reinitializeWebSocket() {
  // 先清理现有连接
  cleanupWebSocket();

  // 延迟后重新初始化
  setTimeout(() => {
    setupWebSocket();
  }, 500);
}
