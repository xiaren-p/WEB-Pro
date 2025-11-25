# 文件管理微模块已下线

此文档曾描述 `filemgr` 微模块的接口与行为。该模块在 2025-11 已从代码库下线：

- 对应的路由已从 `api_v1/urls.py` 中移除；
- 运行时实现已删除；
- 如需恢复，请基于历史提交或分支恢复原有迁移与实现。

保留此文件仅作历史说明。若需要我可以将其从仓库中完全删除。
- 令牌读取：`src/utils/auth.ts` 已适配从主应用读取 `vea:auth:access_token`；请求头自动加 `Bearer` 前缀。
- recycle 页：`POST merge/deleteSumFile` 现在是“回收站列表”而非“删除”，保持兼容调用签名即可。

## 可选优化

- 合并成功后自动清理分片文件以节省空间。
- 支持分片并发上传与校验更高效的检查（例如记录缺失的分片序号而非 hash 列表）。
- 引入对象存储（MinIO/S3）替代本地 `MEDIA_ROOT`。
- 为回收站添加前端“彻底删除”按钮，调用 `/merge/deleteForever`。

## 外链接入与菜单配置

主项目通过“菜单管理”模块的 `type=4`（外链）来接入独立的文件管理前端（chunk_front）。后端在构建路由 (`/api/v1/menus/routes`) 时会将外链菜单转换为内部占位路由（形如 `/ext-<menuId>`），并在 `meta.link` 中保留原始外链；前端渲染时直接使用 `meta.external` + `meta.link` 以 `<a target="_blank">` 打开，无需实际路由跳转，从而避免 Element Plus 表单宽度计算问题。

### 创建外链菜单示例

请求：`POST /api/v1/menus`

Body（关键字段）：

```jsonc
{
  "type": 4,                 // 外链类型
  "name": "文件管理",        // 显示名称
  "path": "https://files.example.com", // 完整 URL（可含端口）
  "component": "",          // 可留空；后端会替换为占位组件 external/redirect
  "parentId": "0",          // 放在顶层或某一分组下
  "icon": "Folder",         // 选择合适图标
  "keepAlive": false,
  "hide": false,
  "sort": 20
}
```

返回成功后，前端拉取路由时获得：

```jsonc
{
  "path": "/ext-823740192",  // 自动生成的占位路径
  "component": "external/redirect",
  "meta": {
    "title": "文件管理",
    "icon": "Folder",
    "external": true,
    "link": "https://files.example.com" // 原始外链
  }
}
```

前端菜单组件检测到 `meta.external` 后：

- 不执行 `router.push(path)`。
- 渲染成 `<a href={meta.link} target="_blank" rel="noopener">`。
- 避免重复挂载/卸载导致的布局测量异常。

### 携带令牌的方式（可选）

若外部文件管理前端与主域不同，且无法直接访问主应用 LocalStorage，可在菜单的 `path` 中附加 query：

`https://files.example.com?token=${accessToken}`

前端渲染时保持此 URL；chunk_front 入口脚本中可在 `mounted` 阶段解析：

```ts
// chunk_front main.ts 伪代码
const url = new URL(window.location.href)
const token = url.searchParams.get('token')
if (token) {
  localStorage.setItem('vea:auth:access_token', token)
}
```

之后 Axios 拦截器即可统一注入 `Authorization: Bearer <token>`。

安全建议：

- 使用 HTTPS，避免中间人窃取 query。
- 令牌设置较短有效期（结合 refresh token 机制）。
- 服务端可在检测到 `token` 来自 query 且首次访问时，返回一次性重定向（清除浏览器地址栏 token），前端保存到 storage 后刷新。

### 常见问题排查

| 问题 | 可能原因 | 处理方案 |
|------|----------|----------|
| 外链点击 403 | 外部前端首轮请求未携带 Authorization | 放宽 `/filemgr/auth/doLogin` 与 `/filemgr/user/info` 权限或使用携带 token 的外链形式 |
| 无限刷新 / 重复打开新标签 | 菜单仍在使用内部路由跳转 | 确认菜单组件中 `meta.external` 分支使用 `<a>` 而非 `router.push` |
| Element Plus 表单宽度 0 警告 | 外链路由被当作普通路由导致频繁卸载 | 使用 anchor 打开新标签或 iframe 内嵌并延迟渲染表单 |
| 图片/文件 URL 404 | 外部前端资源基地址与后端不一致 | 后端返回绝对 URL（已默认）；确保 nginx 反向代理路径一致 |

### 升级注意

若后端未来调整外链路由生成策略（例如统一前缀 `/external/`），仅需前端继续使用 `meta.link` 即可；占位路径不用于实际跳转，不会影响现有外链。

