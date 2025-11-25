import type { RouteRecordRaw } from "vue-router";
import { constantRoutes } from "@/router";
import { store } from "@/store";
import router from "@/router";

import { MenuAPI, type RouteVO } from "@/backend";
const modules = import.meta.glob("../../views/**/**.vue");
const Layout = () => import("../../layouts/index.vue");

export const usePermissionStore = defineStore("permission", () => {
  // 所有路由（静态路由 + 动态路由）
  const routes = ref<RouteRecordRaw[]>([]);
  // 混合布局的左侧菜单路由
  const mixLayoutSideMenus = ref<RouteRecordRaw[]>([]);
  // 动态路由是否已生成
  const isRouteGenerated = ref(false);

  /** 生成动态路由 */
  async function generateRoutes(): Promise<RouteRecordRaw[]> {
    try {
      const data = await MenuAPI.getRoutes(); // 获取当前登录人的菜单路由
      const dynamicRoutes = transformRoutes(data);

      routes.value = [...constantRoutes, ...dynamicRoutes];
      isRouteGenerated.value = true;

      return dynamicRoutes;
    } catch (error) {
      // 路由生成失败，重置状态
      isRouteGenerated.value = false;
      throw error;
    }
  }

  /** 设置混合布局左侧菜单 */
  const setMixLayoutSideMenus = (parentPath: string) => {
    const parentMenu = routes.value.find((item) => item.path === parentPath);
    mixLayoutSideMenus.value = parentMenu?.children || [];
  };

  /** 重置路由状态 */
  const resetRouter = () => {
    // 移除动态添加的路由
    const constantRouteNames = new Set(constantRoutes.map((route) => route.name).filter(Boolean));
    routes.value.forEach((route) => {
      if (route.name && !constantRouteNames.has(route.name)) {
        router.removeRoute(route.name);
      }
    });

    // 重置所有状态
    routes.value = [...constantRoutes];
    mixLayoutSideMenus.value = [];
    isRouteGenerated.value = false;
  };

  return {
    routes,
    mixLayoutSideMenus,
    isRouteGenerated,
    generateRoutes,
    setMixLayoutSideMenus,
    resetRouter,
  };
});

/**
 * 转换后端路由数据为Vue Router配置
 * 处理组件路径映射和Layout层级嵌套
 */
// 需要在前端强制排除的动态路由（后端暂未下线的情况下做临时隐藏）
// 可以根据 path / name / meta.title 三种方式匹配
const EXCLUDED_ROUTE_PATHS = new Set([
  "/system/dict-item",
  "/system/dictItem",
  "/system/dict/item",
]);
const EXCLUDED_ROUTE_NAMES = new Set(["DictItem", "DictItemManage", "DictItemManagement"]);
const EXCLUDED_ROUTE_TITLES = new Set(["字典项管理", "字典项", "字典项维护"]);

const transformRoutes = (routes: RouteVO[], isTopLevel: boolean = true): RouteRecordRaw[] => {
  return routes
    .map((route) => {
      const { component, children, ...args } = route;
      const processedComponent = isTopLevel || component !== "Layout" ? component : undefined;
      const normalizedRoute = { ...args } as RouteRecordRaw;

      // 命中排除条件：不删除路由，仅隐藏菜单项
      if (
        (route.path && EXCLUDED_ROUTE_PATHS.has(route.path)) ||
        (route.name && EXCLUDED_ROUTE_NAMES.has(route.name)) ||
        (route.meta?.title && EXCLUDED_ROUTE_TITLES.has(route.meta.title))
      ) {
        normalizedRoute.meta = { ...(normalizedRoute.meta || {}), hidden: true } as any;
      }

      if (!processedComponent) {
        normalizedRoute.component = undefined;
      } else {
        normalizedRoute.component =
          processedComponent === "Layout"
            ? Layout
            : modules[`../../views/${processedComponent}.vue`] ||
              modules[`../../views/error/404.vue`];
      }

      if (children && children.length > 0) {
        const childTransformed = transformRoutes(children, false);
        if (childTransformed.length > 0) {
          normalizedRoute.children = childTransformed;
        }
      }
      return normalizedRoute;
    })
    .filter((r): r is RouteRecordRaw => !!r);
};

/** 非组件环境使用权限store */
export function usePermissionStoreHook() {
  return usePermissionStore(store);
}
