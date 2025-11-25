# 后端（Django + DRF）说明

本项目为前后端分离的后端部分，使用 Django + DRF 实现，路径与前端严格对齐，返回结构统一。

## 文件管理模块下线说明

原“文件管理”模块（上传/分享/回收站/ACL 等功能）已在 2025-11 彻底下线，涉及：

1. 移除所有相关 Django 模型（FileEntry / FileObject / FileShare / FileEntryAccess / HashTask） — 参见迁移 `0011_remove_hashtask_entry_remove_hashtask_parent_and_more.py`。
2. 清理前端页面 `system/file/index.vue`，现为占位空视图；路由 /system/file 不再显示实际文件功能。
3. 移除用于预览的依赖 `marked`、`highlight.js`。
4. 更新同步命令 `sync_system_menus`：不再生成“文件管理”菜单及其 `sys:file:*` 按钮权限，并额外清理历史残留。
5. 新增命令：

- `python manage.py purge_file_module_artifacts` 清除遗留菜单与角色关联，`--with-logs` 可额外删除历史操作日志中与文件相关的记录。
- `python manage.py audit_orphans` 审计潜在孤立外键（整体数据健康度快速检查）。

### 升级 / 回滚提示

旧版本升级步骤：

```powershell
python manage.py migrate
python manage.py sync_system_menus
python manage.py purge_file_module_artifacts --with-logs
python manage.py audit_orphans
```

回滚访问旧文件数据：仅可通过迁移前数据库备份恢复；表结构已删除不可直接反向。若需重新引入，请基于历史版本分支 cherry-pick 后重新创建迁移（建议使用新表前缀避免冲突）。

### 保留脚本

- purge_file_module_artifacts：确保生产环境中不再出现 `sys:file:*` 权限以及“文件管理”菜单。
- audit_orphans：发现未来新增模型的孤立外键；与文件模块无强绑定，可长期使用。

### 影响评估

- 数据库体积：删除文件相关表后 DB 与 media 目录体积下降；请手动检查 `media/uploads/*` 是否有孤立物理文件再行清理或归档。
- 权限体系：角色中旧 `sys:file:*` 标识失效；菜单同步命令会清理残留按钮避免前端空权限点。
- 前端代码：若存在自定义依赖旧文件接口的逻辑，需先实现替代方案再升级。

### 后续建议

- 若仍需上传能力，建议针对业务设计精简的“附件”子模块，而非恢复通用文件盘。
- 考虑使用对象存储（S3 / OSS 等）分离文件生命周期与扩展能力（版本化、生命周期策略）。

需要重新设计新的文件/附件子模块时，可参考先前特性（秒传 / 去重 / 异步哈希 / 分组展示 等）。

## 外部文件管理（说明）

内置的文件管理微模块已在 2025-11 下线，相关后端实现与路由均已移除。若需要再次接入外部文件管理前端，请基于历史提交恢复相应实现或实现新的附件子模块。有关如何替换或重建附件功能，我可以协助设计并给出可行方案。
