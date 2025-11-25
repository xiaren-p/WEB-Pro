import { Storage } from "./storage";
import { AUTH_KEYS, ROLE_ROOT } from "@/constants";
import { useUserStoreHook } from "@/store/modules/user-store";
import router from "@/router";

// 负责本地凭证与偏好的读写
export const AuthStorage = {
  getAccessToken(): string {
    // 为兼容不同 tab 的登录保持，默认从 localStorage 读取 access token。
    // 以前根据 rememberMe 在 sessionStorage/localStorage 切换，导致新标签页无法共享 sessionStorage。
    // 这里优先使用 localStorage（持久化），若不存在再回退到 sessionStorage。
    const local = Storage.get<string>(AUTH_KEYS.ACCESS_TOKEN, "");
    if (local) return local;
    return Storage.sessionGet(AUTH_KEYS.ACCESS_TOKEN, "");
  },

  getRefreshToken(): string {
    // 同 access token，优先从 localStorage 读取刷新令牌以支持跨标签页刷新流程。
    const local = Storage.get<string>(AUTH_KEYS.REFRESH_TOKEN, "");
    if (local) return local;
    return Storage.sessionGet(AUTH_KEYS.REFRESH_TOKEN, "");
  },

  setTokens(accessToken: string, refreshToken: string, rememberMe: boolean): void {
    // 将 rememberMe 标记写入 localStorage（用于下次启动界面展示）
    Storage.set(AUTH_KEYS.REMEMBER_ME, rememberMe);
    // 为了避免新标签页无法共享登录状态的问题，默认同时在 localStorage 写入令牌。
    // 如果用户不希望持久化，可在 UI 中选择不记住（未来可扩展为 HttpOnly cookie 方案）。
    try {
      Storage.set(AUTH_KEYS.ACCESS_TOKEN, accessToken);
      Storage.set(AUTH_KEYS.REFRESH_TOKEN, refreshToken);
      // 仍在 sessionStorage 保持一份，兼容当前会话读取逻辑
      Storage.sessionSet(AUTH_KEYS.ACCESS_TOKEN, accessToken);
      Storage.sessionSet(AUTH_KEYS.REFRESH_TOKEN, refreshToken);
    } catch (e) {
      // 兜底：若 localStorage 不可用（隐身模式等），仅写 sessionStorage
      Storage.sessionSet(AUTH_KEYS.ACCESS_TOKEN, accessToken);
      Storage.sessionSet(AUTH_KEYS.REFRESH_TOKEN, refreshToken);
    }
  },

  clearAuth(): void {
    Storage.remove(AUTH_KEYS.ACCESS_TOKEN);
    Storage.remove(AUTH_KEYS.REFRESH_TOKEN);
    Storage.sessionRemove(AUTH_KEYS.ACCESS_TOKEN);
    Storage.sessionRemove(AUTH_KEYS.REFRESH_TOKEN);
  },

  getRememberMe(): boolean {
    return Storage.get<boolean>(AUTH_KEYS.REMEMBER_ME, false);
  },
};

/**
 * 权限判断
 */
export function hasPerm(value: string | string[], type: "button" | "role" = "button"): boolean {
  const { roles, perms } = useUserStoreHook().userInfo;

  // 超级管理员拥有所有权限
  if (type === "button" && roles.includes(ROLE_ROOT)) {
    return true;
  }

  const auths = type === "button" ? perms : roles;
  return typeof value === "string"
    ? auths.includes(value)
    : value.some((perm) => auths.includes(perm));
}

/**
 * 重定向到登录页面
 */
export async function redirectToLogin(message: string = "请重新登录"): Promise<void> {
  try {
    ElNotification({
      title: "提示",
      message,
      type: "warning",
      duration: 3000,
    });

    await useUserStoreHook().resetAllState();

    // 跳转到登录页，保留当前路由用于登录后跳转
    const currentPath = router.currentRoute.value.fullPath;
    await router.push(`/login?redirect=${encodeURIComponent(currentPath)}`);
  } catch (error) {
    console.error("Redirect to login error:", error);
  }
}
