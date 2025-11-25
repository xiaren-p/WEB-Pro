import request from "@/utils/request";

// Consolidated backend helpers (not under src/api).
// Only the endpoints still used by dashboard and system pages are included.

// ---- Menu ----
export interface Meta {
  alwaysShow?: boolean;
  hidden?: boolean;
  icon?: string;
  keepAlive?: boolean;
  title?: string;
}
export interface RouteVO {
  children?: RouteVO[];
  component?: string;
  meta?: Meta;
  name?: string;
  path?: string;
  redirect?: string;
}

export interface MenuQuery {
  keywords?: string;
}
export interface MenuVO {
  id?: string;
  parentId?: string;
  name?: string;
  type?: number; // 1目录 2菜单 3按钮 4外链
  routeName?: string; // 后端字段 routeName
  path?: string; // 后端字段 path
  component?: string;
  perms?: string; // 后端字段 perms
  icon?: string;
  sort?: number;
  visible?: number; // 1显示 0隐藏
  status?: number;
  children?: MenuVO[];
}
export interface MenuForm {
  id?: string;
  parentId?: string;
  name?: string;
  type?: number;
  routeName?: string;
  path?: string;
  component?: string;
  perms?: string;
  icon?: string;
  sort?: number;
  visible?: number;
  status?: number;
}

// 注意：这里的路径不包含 /api/v1 前缀
// 在开发环境下，/dev-api 代理会把前缀重写并转发到 VITE_APP_API_URL（已包含 /api/v1）
// 例如：/dev-api + /menus -> http://127.0.0.1:8000/api/v1/menus
const MENU_BASE_URL = "/menus";
// 将前端 MenuForm 与后端字段对齐
function mapToBackend(data: MenuForm) {
  // 过滤 undefined，避免覆盖
  const payload: any = {};
  if (data.name !== undefined) payload.name = data.name;
  if (data.parentId !== undefined) payload.parentId = data.parentId;
  if (data.type !== undefined) payload.type = data.type;
  if (data.routeName !== undefined) payload.routeName = data.routeName;
  if (data.path !== undefined) payload.path = data.path;
  if (data.component !== undefined) payload.component = data.component;
  if (data.perms !== undefined) payload.perms = data.perms;
  if (data.icon !== undefined) payload.icon = data.icon;
  if (data.sort !== undefined) payload.sort = data.sort;
  if (data.visible !== undefined) payload.visible = data.visible;
  if (data.status !== undefined) payload.status = data.status;
  return payload;
}
export const MenuAPI = {
  getRoutes() {
    return request<any, RouteVO[]>({ url: `${MENU_BASE_URL}/routes`, method: "get" });
  },
  getList(queryParams: MenuQuery) {
    // 保留旧 list 接口
    return request<any, MenuVO[]>({ url: `${MENU_BASE_URL}`, method: "get", params: queryParams });
  },
  getTree() {
    return request<any, MenuVO[]>({ url: `${MENU_BASE_URL}/tree`, method: "get" });
  },
  getOptions(onlyParent?: boolean) {
    return request<any, any[]>({
      url: `${MENU_BASE_URL}/options`,
      method: "get",
      params: { onlyParent },
    });
  },
  getFormData(id: string) {
    return request<any, MenuForm>({ url: `${MENU_BASE_URL}/${id}/form`, method: "get" });
  },
  create(data: MenuForm) {
    return request({ url: `${MENU_BASE_URL}`, method: "post", data: mapToBackend(data) });
  },
  update(id: string, data: MenuForm) {
    return request({ url: `${MENU_BASE_URL}/${id}`, method: "put", data: mapToBackend(data) });
  },
  deleteById(id: string) {
    return request({ url: `${MENU_BASE_URL}/${id}`, method: "delete" });
  },
};

// ---- User ----
const USER_BASE_URL = "/users";
export interface PageResult<T> {
  total: number;
  list: T;
}
export interface PageQuery {
  pageNum: number;
  pageSize: number;
}

export interface UserPageQuery extends PageQuery {
  keywords?: string;
  status?: number;
  deptId?: string;
  createTime?: [string, string];
}
export interface UserPageVO {
  id: string;
  username?: string;
  nickname?: string;
  avatar?: string;
  email?: string;
  mobile?: string;
  gender?: number;
  deptName?: string;
  roleNames?: string;
  status?: number;
  createTime?: Date;
}
export interface UserForm {
  id?: string;
  avatar?: string;
  deptId?: string;
  email?: string;
  gender?: number;
  mobile?: string;
  nickname?: string;
  roleIds?: number[];
  status?: number;
  username?: string;
  password?: string;
}
export interface UserInfo {
  userId?: string;
  username?: string;
  nickname?: string;
  avatar?: string;
  roles: string[];
  perms: string[];
}

export const UserAPI = {
  getInfo() {
    return request<
      any,
      {
        userId?: string;
        username?: string;
        nickname?: string;
        avatar?: string;
        roles: string[];
        perms: string[];
      }
    >({ url: `${USER_BASE_URL}/me`, method: "get" });
  },
  getPage(queryParams: UserPageQuery) {
    return request<any, PageResult<UserPageVO[]>>({
      url: `${USER_BASE_URL}/page`,
      method: "get",
      params: queryParams,
    });
  },
  getFormData(userId: string) {
    return request<any, UserForm>({ url: `${USER_BASE_URL}/${userId}/form`, method: "get" });
  },
  create(data: UserForm) {
    return request({ url: `${USER_BASE_URL}`, method: "post", data });
  },
  update(id: string, data: UserForm) {
    return request({ url: `${USER_BASE_URL}/${id}`, method: "put", data });
  },
  resetPassword(id: string, password: string) {
    return request({
      url: `${USER_BASE_URL}/${id}/password/reset`,
      method: "put",
      params: { password },
    });
  },
  deleteByIds(ids: string) {
    return request({ url: `${USER_BASE_URL}/${ids}`, method: "delete" });
  },
  downloadTemplate() {
    return request({ url: `${USER_BASE_URL}/template`, method: "get", responseType: "blob" });
  },
  export(queryParams: UserPageQuery) {
    return request({
      url: `${USER_BASE_URL}/export`,
      method: "get",
      params: queryParams,
      responseType: "blob",
    });
  },
  import(deptId: string, file: File) {
    const formData = new FormData();
    formData.append("file", file);
    // 不显式设置 Content-Type，交由浏览器自动生成带 boundary 的 multipart 头
    return request<any, any>({
      url: `${USER_BASE_URL}/import`,
      method: "post",
      params: { deptId },
      data: formData,
    });
  },
  getProfile() {
    return request<any, any>({ url: `${USER_BASE_URL}/profile`, method: "get" });
  },
  updateProfile(data: any) {
    return request({ url: `${USER_BASE_URL}/profile`, method: "put", data });
  },
  changePassword(data: any) {
    return request({ url: `${USER_BASE_URL}/password`, method: "put", data });
  },
  sendMobileCode(mobile: string) {
    return request({ url: `${USER_BASE_URL}/mobile/code`, method: "post", params: { mobile } });
  },
  bindOrChangeMobile(data: any) {
    return request({ url: `${USER_BASE_URL}/mobile`, method: "put", data });
  },
  sendEmailCode(email: string) {
    return request({ url: `${USER_BASE_URL}/email/code`, method: "post", params: { email } });
  },
  bindOrChangeEmail(data: any) {
    return request({ url: `${USER_BASE_URL}/email`, method: "put", data });
  },
  getOptions() {
    return request<any, any[]>({ url: `${USER_BASE_URL}/options`, method: "get" });
  },
  uploadAvatar(file: File, cloudPassword?: string) {
    const form = new FormData();
    form.append("file", file);
    if (cloudPassword) {
      form.append("cloudPassword", cloudPassword);
    }
    return request<any, { url: string; name: string; seafileAvatarSync?: any }>({
      url: `${USER_BASE_URL}/avatar`,
      method: "post",
      data: form,
    });
  },
  createCloudUsers(ids: Array<string | number>, passwords: Record<string, string>) {
    return request<any, any>({
      url: `${USER_BASE_URL}/cloud-create`,
      method: "post",
      data: { ids, passwords },
    });
  },
};

// ---- Upload (Lightweight) ----
const UPLOAD_BASE_URL = "/users"; // using /users/upload-image endpoint
export interface ImageUploadResult {
  url: string;
  name?: string;
  width?: number;
  height?: number;
  size?: number;
  thumbs?: Record<string, string>;
}
export const UploadAPI = {
  uploadImage(file: File, thumbs?: Array<number | string>) {
    const form = new FormData();
    form.append("file", file);
    const params: any = {};
    if (thumbs && thumbs.length) params.thumbs = thumbs.join(",");
    return request<any, ImageUploadResult>({
      url: `${UPLOAD_BASE_URL}/upload-image`,
      method: "post",
      data: form,
      params,
    });
  },
};

// ---- Role ----
const ROLE_BASE_URL = "/roles";
export interface RolePageQuery extends PageQuery {
  keywords?: string;
}
export interface RolePageVO {
  id: string;
  name?: string;
  code?: string;
  sort?: number;
  status?: number;
}
export interface RoleForm {
  id?: string;
  name?: string;
  code?: string;
  sort?: number;
  status?: number;
  dataScope?: number;
}
export const RoleAPI = {
  getPage(params: RolePageQuery) {
    return request<any, PageResult<RolePageVO[]>>({
      url: `${ROLE_BASE_URL}/page`,
      method: "get",
      params,
    });
  },
  getOptions() {
    return request<any, any[]>({ url: `${ROLE_BASE_URL}/options`, method: "get" });
  },
  getFormData(id: string) {
    return request<any, RoleForm>({ url: `${ROLE_BASE_URL}/${id}/form`, method: "get" });
  },
  create(data: RoleForm) {
    return request({ url: `${ROLE_BASE_URL}`, method: "post", data });
  },
  update(id: string, data: RoleForm) {
    return request({ url: `${ROLE_BASE_URL}/${id}`, method: "put", data });
  },
  deleteByIds(ids: string) {
    return request({ url: `${ROLE_BASE_URL}/${ids}`, method: "delete" });
  },
  getMenuIds(roleId: string) {
    return request<any, string[]>({ url: `${ROLE_BASE_URL}/${roleId}/menuIds`, method: "get" });
  },
  saveMenus(roleId: string, menuIds: Array<string | number>) {
    return request({ url: `${ROLE_BASE_URL}/${roleId}/menus`, method: "put", data: menuIds });
  },
  // aliases for existing code in views
  getRoleMenuIds(roleId: string) {
    return this.getMenuIds(roleId);
  },
  updateRoleMenus(roleId: string, menuIds: Array<string | number>) {
    return this.saveMenus(roleId, menuIds);
  },
};

// ---- Dept ----
const DEPT_BASE_URL = "/depts"; // align when backend adds
export interface DeptQuery extends PageQuery {
  keywords?: string;
  status?: number;
}
export interface DeptVO {
  id: string;
  parentId?: string;
  name?: string;
  code?: string;
  status?: number;
  sort?: number;
  children?: DeptVO[];
}
export interface DeptForm {
  id?: string;
  parentId?: string;
  name?: string;
  code?: string;
  sort?: number;
  status?: number;
}
export const DeptAPI = {
  getList(params: DeptQuery) {
    return request<any, DeptVO[]>({ url: `${DEPT_BASE_URL}`, method: "get", params });
  },
  getOptions() {
    return request<any, any[]>({ url: `${DEPT_BASE_URL}/options`, method: "get" });
  },
  getTree() {
    return request<any, DeptVO[]>({ url: `${DEPT_BASE_URL}/tree`, method: "get" });
  },
  getFormData(id: string) {
    return request<any, DeptForm>({ url: `${DEPT_BASE_URL}/${id}/form`, method: "get" });
  },
  create(data: DeptForm) {
    return request({ url: `${DEPT_BASE_URL}`, method: "post", data });
  },
  update(id: string, data: DeptForm) {
    return request({ url: `${DEPT_BASE_URL}/${id}`, method: "put", data });
  },
  deleteByIds(ids: string) {
    return request({ url: `${DEPT_BASE_URL}/${ids}`, method: "delete" });
  },
};

// ---- Dict ----
const DICT_BASE_URL = "/dicts";
export interface DictPageQuery extends PageQuery {
  keywords?: string;
}
export interface DictPageVO {
  id: string;
  name?: string;
  dictCode?: string;
  status?: number;
  remark?: string;
}
export interface DictForm {
  id?: string;
  name?: string;
  dictCode?: string;
  status?: number;
  remark?: string;
}
export interface DictItemPageQuery extends PageQuery {
  keywords?: string;
}
export interface DictItemPageVO {
  id: string;
  label?: string;
  value?: string;
  status?: number;
  sort?: number;
  tagType?: string;
}
export interface DictItemForm {
  id?: string;
  dictCode?: string;
  label?: string;
  value?: string;
  status?: number;
  sort?: number;
  tagType?: string;
}
export interface DictItemOption {
  label: string;
  value: any;
  colorType?: string;
  cssClass?: string;
  tagType?: string;
}
export const DictAPI = {
  getPage(params: DictPageQuery) {
    return request<any, PageResult<DictPageVO[]>>({
      url: `${DICT_BASE_URL}/page`,
      method: "get",
      params,
    });
  },
  getList() {
    return request<any, DictPageVO[]>({ url: `${DICT_BASE_URL}`, method: "get" });
  },
  getFormData(id: string) {
    return request<any, DictForm>({ url: `${DICT_BASE_URL}/${id}/form`, method: "get" });
  },
  create(data: DictForm) {
    return request({ url: `${DICT_BASE_URL}`, method: "post", data });
  },
  update(id: string, data: DictForm) {
    return request({ url: `${DICT_BASE_URL}/${id}`, method: "put", data });
  },
  deleteByIds(ids: string) {
    return request({ url: `${DICT_BASE_URL}/${ids}`, method: "delete" });
  },
  getItemPage(dictCode: string, params: DictItemPageQuery) {
    return request<any, PageResult<DictItemPageVO[]>>({
      url: `${DICT_BASE_URL}/${dictCode}/items/page`,
      method: "get",
      params,
    });
  },
  getItemForm(dictCode: string, itemId: string) {
    return request<any, DictItemForm>({
      url: `${DICT_BASE_URL}/${dictCode}/items/${itemId}/form`,
      method: "get",
    });
  },
  createItem(dictCode: string, data: DictItemForm) {
    return request({ url: `${DICT_BASE_URL}/${dictCode}/items`, method: "post", data });
  },
  updateItem(dictCode: string, itemId: string, data: DictItemForm) {
    return request({ url: `${DICT_BASE_URL}/${dictCode}/items/${itemId}`, method: "put", data });
  },
  deleteItems(dictCode: string, ids: string) {
    return request({ url: `${DICT_BASE_URL}/${dictCode}/items/${ids}`, method: "delete" });
  },
  getItemOptions(dictCode: string) {
    return request<any, DictItemOption[]>({
      url: `${DICT_BASE_URL}/${dictCode}/items/options`,
      method: "get",
    });
  },
  // compatibility alias methods used by some views
  getDictItemPage(dictCode: string, params: DictItemPageQuery) {
    return this.getItemPage(dictCode, params);
  },
  getDictItemFormData(dictCode: string, itemId: string) {
    return this.getItemForm(dictCode, itemId);
  },
  updateDictItem(dictCode: string, itemId: string, data: DictItemForm) {
    return this.updateItem(dictCode, itemId, data);
  },
  createDictItem(dictCode: string, data: DictItemForm) {
    return this.createItem(dictCode, data);
  },
  deleteDictItems(dictCode: string, ids: string) {
    return this.deleteItems(dictCode, ids);
  },
};

// ---- Crawler Conf (数据采集节点) ----
const CRAWLER_BASE_URL = "/crawler/conf";
export interface CrawlerConfVO {
  id?: string;
  server_name?: string;
  node?: string;
  ip?: string;
  status?: number;
  order_num?: number;
}
export interface CrawlerConfForm {
  id?: string;
  server_name?: string;
  node?: string;
  ip?: string;
  status?: number;
  order_num?: number;
}
export const CrawlerAPI = {
  getList(params: any) {
    return request<any, CrawlerConfVO[]>({ url: `${CRAWLER_BASE_URL}`, method: "get", params });
  },
  getFormData(id: string) {
    return request<any, CrawlerConfForm>({ url: `${CRAWLER_BASE_URL}/${id}/form`, method: "get" });
  },
  create(data: CrawlerConfForm) {
    return request({ url: `${CRAWLER_BASE_URL}`, method: "post", data });
  },
  update(id: string, data: CrawlerConfForm) {
    return request({ url: `${CRAWLER_BASE_URL}/${id}`, method: "put", data });
  },
  deleteByIds(ids: string) {
    return request({ url: `${CRAWLER_BASE_URL}/${ids}`, method: "delete" });
  },
};

// ---- Crawler Category (前端使用的类目采集接口占位) ----
const CATEGORY_BASE_URL = "/crawler/category";
export interface CategoryPageQuery extends PageQuery {
  keywords?: string;
  site?: string;
}
export interface CategoryVO {
  id?: string;
  name?: string;
  category_id?: string;
  site?: string;
  category_type?: string;
  status?: number;
}
export interface CategoryForm {
  id?: string;
  name?: string;
  category_id?: string;
  site?: string;
  category_type?: string;
  status?: number;
}
export const CategoryAPI = {
  getPage(params: any) {
    return request<any, PageResult<CategoryVO[]>>({
      url: `${CATEGORY_BASE_URL}/page`,
      method: "get",
      params,
    });
  },
  getFormData(id: string) {
    return request<any, CategoryForm>({ url: `${CATEGORY_BASE_URL}/${id}/form`, method: "get" });
  },
  getTimes(id: string) {
    return request<any, { list: { index: number; name: string }[]; all: string[] }>({
      url: `${CATEGORY_BASE_URL}/${id}/times`,
      method: "get",
    });
  },
  checkFile(id: string, time: string) {
    return request<
      any,
      { exists?: boolean; error_msg?: string; viewUrl?: string; downloadUrl?: string }
    >({ url: `${CATEGORY_BASE_URL}/${id}/file/check`, method: "get", params: { time } });
  },
  downloadFile(id: string, time: string) {
    return request<any, Blob>({
      url: `${CATEGORY_BASE_URL}/${id}/file`,
      method: "get",
      params: { time },
      responseType: "blob",
    });
  },
  create(data: CategoryForm) {
    return request({ url: `${CATEGORY_BASE_URL}`, method: "post", data });
  },
  update(id: string, data: CategoryForm) {
    return request({ url: `${CATEGORY_BASE_URL}/${id}`, method: "put", data });
  },
  deleteByIds(ids: string) {
    return request({ url: `${CATEGORY_BASE_URL}/${ids}`, method: "delete" });
  },
};

// ---- Config ----
const CONFIG_BASE_URL = "/configs";
export interface ConfigPageQuery extends PageQuery {
  keywords?: string;
}
export interface ConfigPageVO {
  id: string;
  configName?: string;
  configKey?: string;
  configValue?: string;
  status?: number;
  remark?: string;
}
export interface ConfigForm {
  id?: string;
  configName?: string;
  configKey?: string;
  configValue?: string;
  status?: number;
  remark?: string;
}
export const ConfigAPI = {
  getPage(params: ConfigPageQuery) {
    return request<any, PageResult<ConfigPageVO[]>>({
      url: `${CONFIG_BASE_URL}/page`,
      method: "get",
      params,
    });
  },
  getFormData(id: string) {
    return request<any, ConfigForm>({ url: `${CONFIG_BASE_URL}/${id}/form`, method: "get" });
  },
  create(data: ConfigForm) {
    return request({ url: `${CONFIG_BASE_URL}`, method: "post", data });
  },
  update(id: string, data: ConfigForm) {
    return request({ url: `${CONFIG_BASE_URL}/${id}`, method: "put", data });
  },
  deleteByIds(ids: string) {
    return request({ url: `${CONFIG_BASE_URL}/${ids}`, method: "delete" });
  },
  refreshCache() {
    return request({ url: `${CONFIG_BASE_URL}/refresh-cache`, method: "post" });
  },
  // alias
  deleteById(id: string) {
    return this.deleteByIds(id);
  },
};

// ---- Logs ----
const LOG_BASE_URL = "/logs";
export interface LogPageQuery extends PageQuery {
  keywords?: string;
  createTime?: [string, string];
}
export interface LogPageVO {
  id: string;
  createTime?: string;
  operator?: string;
  module?: string;
  content?: string;
  ip?: string;
  region?: string;
  browser?: string;
  os?: string;
  executionTime?: number;
}
export interface VisitStatsVO {
  todayUvCount: number;
  totalUvCount: number;
  uvGrowthRate: number;
  todayPvCount: number;
  totalPvCount: number;
  pvGrowthRate: number;
}
export interface VisitTrendVO {
  dates: string[];
  pvList: number[];
  uvList: number[];
  ipList: number[];
}
export const LogAPI = {
  getPage(params: LogPageQuery) {
    return request<any, PageResult<LogPageVO[]>>({
      url: `${LOG_BASE_URL}/page`,
      method: "get",
      params,
    });
  },
  getVisitTrend(params?: any) {
    return request<any, VisitTrendVO>({
      url: `${LOG_BASE_URL}/visit-trend`,
      method: "get",
      params,
    });
  },
  getVisitStats(params?: any) {
    return request<any, VisitStatsVO>({
      url: `${LOG_BASE_URL}/visit-stats`,
      method: "get",
      params,
    });
  },
};

// ---- Notice ----
const NOTICE_BASE_URL = "/notices";
export const NoticeAPI = {
  getPage(params: any) {
    return request<any, PageResult<NoticePageVO[]>>({
      url: `${NOTICE_BASE_URL}/page`,
      method: "get",
      params,
    });
  },
  getFormData(id: string) {
    return request<any, any>({ url: `${NOTICE_BASE_URL}/${id}/form`, method: "get" });
  },
  publish(id: string) {
    return request({ url: `${NOTICE_BASE_URL}/${id}/publish`, method: "post" });
  },
  revoke(id: string) {
    return request({ url: `${NOTICE_BASE_URL}/${id}/revoke`, method: "post" });
  },
  getDetail(id: string) {
    return request<any, NoticeDetailVO>({ url: `${NOTICE_BASE_URL}/${id}/detail`, method: "get" });
  },
  read(id: string) {
    return request({ url: `${NOTICE_BASE_URL}/${id}/read`, method: "post" });
  },
  readAll() {
    return request({ url: `${NOTICE_BASE_URL}/read-all`, method: "post" });
  },
  getMyPage(params: any) {
    return request<any, PageResult<NoticePageVO[]>>({
      url: `${NOTICE_BASE_URL}/my-page`,
      method: "get",
      params,
    });
  },
  // alias for existing code usage
  getMyNoticePage(params: any) {
    return this.getMyPage(params);
  },
  create(data: any) {
    return request({ url: `${NOTICE_BASE_URL}`, method: "post", data });
  },
  update(id: string, data: any) {
    return request({ url: `${NOTICE_BASE_URL}/${id}`, method: "put", data });
  },
  deleteByIds(ids: string) {
    return request({ url: `${NOTICE_BASE_URL}/${ids}`, method: "delete" });
  },
};

// Notice types (lightweight)
export type NoticePageQuery = PageQuery & {
  title?: string;
  publishStatus?: number;
  isRead?: number;
};
export interface NoticePageVO {
  id: string;
  title?: string;
  type?: number;
  status?: number;
  creator?: string;
  createTime?: Date;
  publisherName?: string;
  publishTime?: string;
  revokeTime?: string;
  level?: string | number;
  publishStatus?: number;
  targetType?: number;
}
export interface NoticeForm {
  id?: string;
  title?: string;
  content?: string;
  status?: number;
  type?: number;
  receiverType?: number;
  level?: string | number;
  targetType?: number;
  targetUserIds?: string[];
}
export interface NoticeDetailVO {
  id?: string;
  title?: string;
  content?: string;
  publisherName?: string;
  publishTime?: string;
  publishStatus?: number;
}

// ---- Auth (minimal) ----
const AUTH_BASE_URL = "/auth";
export const AuthAPI = {
  login(data: any & { captchaKey?: string; captchaCode?: string }) {
    return request<
      any,
      { accessToken: string; refreshToken: string; tokenType?: string; expiresIn: number }
    >({ url: `${AUTH_BASE_URL}/login`, method: "post", data });
  },
  logout() {
    return request({ url: `${AUTH_BASE_URL}/logout`, method: "delete" });
  },
  refreshToken(refreshToken: string) {
    return request<
      any,
      { accessToken: string; refreshToken?: string; tokenType?: string; expiresIn: number }
    >(
      // Avoid sending cookies or existing Authorization header when refreshing token to
      // prevent CSRF checks or accidental auth failures on the backend.
      {
        url: `${AUTH_BASE_URL}/refresh-token`,
        method: "post",
        data: { refreshToken },
        headers: { Authorization: "no-auth" },
        withCredentials: false,
      }
    );
  },
  // 获取图形验证码：后端返回 {img, uuid}
  getCaptcha() {
    return request<any, { img: string; uuid: string }>({
      url: `${AUTH_BASE_URL}/captcha`,
      method: "get",
      headers: { Authorization: "no-auth" },
    });
  },
};

export interface LoginFormData {
  username: string;
  password: string;
  captchaKey?: string; // 后端返回的 uuid
  captchaCode?: string; // 用户输入的验证码文本
  rememberMe?: boolean;
}

export default {
  MenuAPI,
  UserAPI,
  RoleAPI,
  DeptAPI,
  DictAPI,
  ConfigAPI,
  LogAPI,
  NoticeAPI,
  AuthAPI,
  UploadAPI,
};
