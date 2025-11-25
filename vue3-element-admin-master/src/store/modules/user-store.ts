import { store } from "@/store";

import { AuthAPI, UserAPI, type UserInfo, type LoginFormData } from "@/backend";

import { AuthStorage } from "@/utils/auth";
import { Storage } from "@/utils/storage";
import { STORAGE_KEYS } from "@/constants";
import { usePermissionStoreHook } from "@/store/modules/permission-store";
import { useDictStoreHook } from "@/store/modules/dict-store";
import { useTagsViewStore } from "@/store";
import { cleanupWebSocket } from "@/plugins/websocket";

export const useUserStore = defineStore("user", () => {
  // 用户信息
  const userInfo = ref<UserInfo>({} as UserInfo);
  // 记住我状态
  const rememberMe = ref(AuthStorage.getRememberMe());
  // Seafile 缓存标志：后端登录时返回，表示服务器侧已缓存 Seafile token
  const seafileCached = ref<boolean>(Storage.get(STORAGE_KEYS.SEAFILE_CACHED, false));

  /**
   * 登录
   *
   * @param {LoginFormData}
   * @returns
   */
  function login(formData: LoginFormData) {
    return new Promise<void>((resolve, reject) => {
      AuthAPI.login(formData)
        .then((data) => {
          const { accessToken, refreshToken } = data;
          // 记录后端返回的 seafileCached 标志（若有）
          try {
            // 记录后端返回的 seafileCached 标志（兼容后端返回对象 {cached: bool, msg:...} 或直接布尔）
            const sf = (data as any).seafileCached;
            let cached = false;
            if (sf !== undefined && sf !== null) {
              if (typeof sf === "object" && "cached" in sf) {
                cached = !!sf.cached;
              } else {
                cached = !!sf;
              }
            }
            seafileCached.value = cached;
            Storage.set(STORAGE_KEYS.SEAFILE_CACHED, cached);
          } catch (e) {
            // ignore parsing errors
          }
          // 保存记住我状态和token
          rememberMe.value = !!formData.rememberMe;
          AuthStorage.setTokens(accessToken, refreshToken, rememberMe.value);
          try {
            // 向已打开的外链窗口广播新 token，支持自动注入（若外部前端仍使用该机制）
            // 1) postMessage 给允许域名的已打开窗口（外部接入端会监听 message）
            window.postMessage(
              { type: "VEA_SSO_TOKEN", token: accessToken },
              window.location.origin
            );
            // 2) localStorage 标志（部分场景便于调试/兼容处理）
            if (accessToken) localStorage.setItem("VEA_SSO_TOKEN", accessToken);
          } catch (e) {
            console.warn("[user-store] broadcast token failed", e);
          }
          resolve();
        })
        .catch((error) => {
          reject(error);
        });
    });
  }

  /**
   * 获取用户信息
   *
   * @returns {UserInfo} 用户信息
   */
  function getUserInfo() {
    return new Promise<UserInfo>((resolve, reject) => {
      UserAPI.getInfo()
        .then((data) => {
          if (!data) {
            reject("Verification failed, please Login again.");
            return;
          }
          // 规范化 avatar URL：
          // - 开发环境（有代理 /dev-api）时，将后端返回的绝对地址替换为代理路径，避免前端直接访问后端主机
          // - 生产环境保留后端返回的绝对地址
          try {
            const avatar = (data as any).avatar as string | undefined;
            if (avatar) {
              const normalized = normalizeAvatarForClient(avatar);
              (data as any).avatar = normalized;
            }
          } catch (e) {
            // ignore normalization errors
          }
          Object.assign(userInfo.value, { ...data });
          resolve(data);
        })
        .catch((error) => {
          reject(error);
        });
    });
  }

  /**
   * 将后端返回的 avatar URL 标准化为客户端可用的 URL。
   * 开发模式下（有代理），将绝对后端地址转换为代理前缀 `/dev-api` + 相对路径，
   * 以利用 Vite 的 dev proxy；生产环境保留原值。
   */
  function normalizeAvatarForClient(url: string): string {
    try {
      if (!url) return url;
      // 如果已经是相对路径，直接返回
      if (url.startsWith("/") && !url.startsWith("//")) return url;
      // 如果是以 http(s) 开头的绝对地址
      if (url.startsWith("http://") || url.startsWith("https://")) {
        // 开发环境使用代理前缀访问
        if (import.meta.env.DEV) {
          try {
            const u = new URL(url);
            // 保留 pathname + search
            const path = u.pathname + (u.search || "");
            // 代理前缀（可在 env 中定制）；默认 /dev-api
            const proxyPrefix = import.meta.env.VITE_APP_DEV_API_PREFIX || "/dev-api";
            // 确保最终路径不出现双 /
            return proxyPrefix.replace(/\/$/, "") + path;
          } catch (e) {
            return url;
          }
        }
      }
      return url;
    } catch (e) {
      return url;
    }
  }

  /**
   * 登出
   */
  function logout() {
    // 登出接口失败也不影响本地清理，统一按成功处理
    return new Promise<void>((resolve) => {
      AuthAPI.logout()
        .catch((err) => {
          console.warn("[Logout] API error ignored:", err);
        })
        .finally(() => {
          resetAllState();
          resolve();
        });
    });
  }

  /**
   * 重置所有系统状态
   * 统一处理所有清理工作，包括用户凭证、路由、缓存等
   */
  function resetAllState() {
    // 1. 重置用户状态
    resetUserState();

    // 2. 重置其他模块状态
    // 重置路由
    usePermissionStoreHook().resetRouter();
    // 清除字典缓存
    useDictStoreHook().clearDictCache();
    // 清除标签视图
    useTagsViewStore().delAllViews();

    // 3. 清理 WebSocket 连接
    cleanupWebSocket();
    console.log("[UserStore] WebSocket connections cleaned up");

    return Promise.resolve();
  }

  /**
   * 重置用户状态
   * 仅处理用户模块内的状态
   */
  function resetUserState() {
    // 清除用户凭证
    AuthStorage.clearAuth();
    // 重置用户信息
    userInfo.value = {} as UserInfo;
  }

  /**
   * 刷新 token
   */
  function refreshToken() {
    const refreshToken = AuthStorage.getRefreshToken();

    if (!refreshToken) {
      return Promise.reject(new Error("没有有效的刷新令牌"));
    }

    return new Promise<void>((resolve, reject) => {
      AuthAPI.refreshToken(refreshToken)
        .then((data) => {
          const { accessToken, refreshToken: newRefreshToken } = data;
          // 更新令牌，保持当前记住我状态（判空防止类型提示报错）
          if (accessToken && newRefreshToken) {
            AuthStorage.setTokens(accessToken, newRefreshToken, AuthStorage.getRememberMe());
            try {
              window.postMessage(
                { type: "VEA_SSO_TOKEN", token: accessToken },
                window.location.origin
              );
              localStorage.setItem("VEA_SSO_TOKEN", accessToken);
            } catch (e) {
              console.warn("[user-store] broadcast token failed", e);
            }
          }
          resolve();
        })
        .catch((error) => {
          console.log(" refreshToken  刷新失败", error);
          reject(error);
        });
    });
  }

  return {
    userInfo,
    rememberMe,
    seafileCached,
    isLoggedIn: () => !!AuthStorage.getAccessToken(),
    getUserInfo,
    login,
    logout,
    resetAllState,
    resetUserState,
    refreshToken,
  };
});

/**
 * 在组件外部使用UserStore的钩子函数
 * @see https://pinia.vuejs.org/core-concepts/outside-component-usage.html
 */
export function useUserStoreHook() {
  return useUserStore(store);
}
