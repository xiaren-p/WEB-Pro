"""Simplified sync_system_menus 管理命令

用途：初始化/更新“系统管理”菜单（父菜单 /system、其下子菜单与按钮），并将这些菜单绑定到 admin 角色。
此文件已精简为仅执行菜单的创建/更新与 admin 绑定，便于在部署或初始化时使用。
"""

from django.core.management.base import BaseCommand
from django.db import transaction
from api_v1.models import Menu, Role


SYSTEM_PARENT_DEF = {
    "name": "系统管理",
    "type": 1,
    "path": "/system",
    "component": "Layout",
    "order_num": 99,
    "icon": "setting",
}

CHILD_MENU_DEFS = [
    {"name": "用户管理", "path": "/system/user", "component": "system/user/index", "perms": "", "order_num": 1, "icon": "el-icon-User"},
    {"name": "角色管理", "path": "/system/role", "component": "system/role/index", "perms": "", "order_num": 2, "icon": "role"},
    {"name": "部门管理", "path": "/system/dept", "component": "system/dept/index", "perms": "", "order_num": 3, "icon": "tree"},
    {"name": "菜单管理", "path": "/system/menu", "component": "system/menu/index", "perms": "", "order_num": 4, "icon": "menu"},
    {"name": "字典管理", "path": "/system/dict", "component": "system/dict/index", "perms": "", "order_num": 5, "icon": "dict"},
    {"name": "通知公告", "path": "/system/notice", "component": "system/notice/index", "perms": "", "order_num": 6, "icon": "el-icon-Notification"},
    {"name": "操作日志", "path": "/system/log", "component": "system/log/index", "perms": "", "order_num": 7, "icon": "document"},
    {"name": "参数配置", "path": "/system/config", "component": "system/config/index", "perms": "", "order_num": 8, "icon": "setting"},
]

# 可选：同步数据采集主菜单及配置子菜单（前端已添加时此脚本可确保按钮权限同步）
DATA_COLLECT_PARENT_DEF = {
    "name": "数据采集",
    "type": 1,
    "path": "/data-collect",
    "component": "Layout",
    "order_num":98,
    "icon": "el-icon-Coin",
}

CRAWLER_CHILD_DEFS = [
    {"name": "类目采集", "path": "/crawler/category", "component": "crawler/category/index", "perms": "", "order_num": 1, "icon": "el-icon-Tools"},
    {"name": "选品采集", "path": "/crawler/selection", "component": "crawler/selection/index", "perms": "", "order_num": 2, "icon": "el-icon-Tools"},
    {"name": "日志", "path": "/crawler/logs", "component": "crawler/logs/index", "perms": "", "order_num": 3, "icon": "document"},
    {"name": "配置", "path": "/crawler/conf", "component": "crawler/conf/index", "perms": "", "order_num": 4, "icon": "el-icon-WarnTriangleFilled"},
]

BUTTON_DEFS = {
    "用户管理": [
        {"name": "用户查询", "perms": "sys:user:query", "order_num": 1},
        {"name": "用户新增", "perms": "sys:user:add", "order_num": 2},
        {"name": "用户编辑", "perms": "sys:user:edit", "order_num": 3},
        {"name": "用户删除", "perms": "sys:user:delete", "order_num": 4},
        {"name": "重置密码", "perms": "sys:user:reset-password", "order_num": 5},
        {"name": "用户导入", "perms": "sys:user:import", "order_num": 6},
        {"name": "用户导出", "perms": "sys:user:export", "order_num": 7},
    ],
    "角色管理": [
        {"name": "角色查询", "perms": "sys:role:query", "order_num": 1},
        {"name": "角色新增", "perms": "sys:role:add", "order_num": 2},
        {"name": "角色编辑", "perms": "sys:role:edit", "order_num": 3},
        {"name": "角色删除", "perms": "sys:role:delete", "order_num": 4},
    ],
    "部门管理": [
        {"name": "部门查询", "perms": "sys:dept:query", "order_num": 1},
        {"name": "部门新增", "perms": "sys:dept:add", "order_num": 2},
        {"name": "部门编辑", "perms": "sys:dept:edit", "order_num": 3},
        {"name": "部门删除", "perms": "sys:dept:delete", "order_num": 4},
    ],
    "菜单管理": [
        {"name": "菜单查询", "perms": "sys:menu:query", "order_num": 1},
        {"name": "菜单新增", "perms": "sys:menu:add", "order_num": 2},
        {"name": "菜单编辑", "perms": "sys:menu:edit", "order_num": 3},
        {"name": "菜单删除", "perms": "sys:menu:delete", "order_num": 4},
    ],
    "字典管理": [
        {"name": "字典查询", "perms": "sys:dict:query", "order_num": 1},
        {"name": "字典新增", "perms": "sys:dict:add", "order_num": 2},
        {"name": "字典编辑", "perms": "sys:dict:edit", "order_num": 3},
        {"name": "字典删除", "perms": "sys:dict:delete", "order_num": 4},
        {"name": "字典数据访问", "perms": "sys:dict:item", "order_num": 5},
        {"name": "字典数据查询", "perms": "sys:dict:item:query", "order_num": 6},
        {"name": "字典数据新增", "perms": "sys:dict:item:add", "order_num": 7},
        {"name": "字典数据编辑", "perms": "sys:dict:item:edit", "order_num": 8},
        {"name": "字典数据删除", "perms": "sys:dict:item:delete", "order_num": 9},
    ],
    "通知公告": [
        {"name": "公告查询", "perms": "sys:notice:query", "order_num": 1},
        {"name": "公告新增", "perms": "sys:notice:add", "order_num": 2},
        {"name": "公告编辑", "perms": "sys:notice:edit", "order_num": 3},
        {"name": "公告删除", "perms": "sys:notice:delete", "order_num": 4},
        {"name": "公告发布", "perms": "sys:notice:publish", "order_num": 5},
        {"name": "公告撤回", "perms": "sys:notice:revoke", "order_num": 6},
    ],
    "操作日志": [
        {"name": "日志查看", "perms": "sys:log:view", "order_num": 1},
        {"name": "访问趋势", "perms": "sys:log:trend", "order_num": 2},
        {"name": "访问统计", "perms": "sys:log:stats", "order_num": 3},
    ],
    "参数配置": [
        {"name": "参数查询", "perms": "sys:config:query", "order_num": 1},
        {"name": "参数新增", "perms": "sys:config:add", "order_num": 2},
        {"name": "参数编辑", "perms": "sys:config:edit", "order_num": 3},
        {"name": "参数删除", "perms": "sys:config:delete", "order_num": 4},
    ],
}

# 数据采集 - 按钮权限（按钮权限标识遵循前端要求 pc:conf:*）
CRAWLER_BUTTON_DEFS = {
    "配置": [
        {"name": "配置查询", "perms": "pc:conf:query", "order_num": 1},
        {"name": "配置新增", "perms": "pc:conf:add", "order_num": 2},
        {"name": "配置编辑", "perms": "pc:conf:edit", "order_num": 3},
        {"name": "配置删除", "perms": "pc:conf:delete", "order_num": 4},
    ],
    "类目采集": [
        {"name": "类目查询", "perms": "pc:category:query", "order_num": 1},
        {"name": "类目新增", "perms": "pc:category:add", "order_num": 2},
        {"name": "类目编辑", "perms": "pc:category:edit", "order_num": 3},
        {"name": "类目删除", "perms": "pc:category:delete", "order_num": 4},
        {"name": "数据查看", "perms": "pc:category:dk", "order_num": 5},
    ],
}


class Command(BaseCommand):
    help = "Sync system management menu tree (init/update) and bind to admin role"

    @transaction.atomic
    def handle(self, *args, **options):
        # Create/update parent
        parent, created = Menu.objects.get_or_create(name=SYSTEM_PARENT_DEF["name"], defaults=SYSTEM_PARENT_DEF)
        if not created:
            for k, v in SYSTEM_PARENT_DEF.items():
                setattr(parent, k, v)
            parent.save()

        created_children = 0
        updated_children = 0

        # Create/update children
        for item in CHILD_MENU_DEFS:
            m, c = Menu.objects.get_or_create(
                name=item["name"], parent=parent,
                defaults={
                    "type": 2,
                    "path": item["path"],
                    "component": item["component"],
                    "perms": item.get("perms", ""),
                    "icon": item.get("icon", ""),
                    "order_num": item.get("order_num", 0),
                    "visible": True,
                    "status": True,
                }
            )
            if c:
                created_children += 1
            else:
                changed = False
                for attr in ("path", "component", "perms", "icon", "order_num"):
                    new_val = item.get(attr)
                    if getattr(m, attr) != new_val:
                        setattr(m, attr, new_val)
                        changed = True
                if changed:
                    m.save()
                    updated_children += 1

            # Sync button permissions under this child (if defined)
            btn_defs = BUTTON_DEFS.get(item["name"], [])
            for b in btn_defs:
                bm, created_btn = Menu.objects.get_or_create(
                    name=b["name"], parent=m,
                    defaults={
                        "type": 3,
                        "path": "",
                        "component": "",
                        "perms": b.get("perms", ""),
                        "icon": "",
                        "order_num": b.get("order_num", 0),
                        "visible": True,
                        "status": True,
                    }
                )
                if not created_btn:
                    changed = False
                    if bm.perms != b.get("perms", ""):
                        bm.perms = b.get("perms", "")
                        changed = True
                    if bm.order_num != b.get("order_num", 0):
                        bm.order_num = b.get("order_num", 0)
                        changed = True
                    if changed:
                        bm.save()

            # 同步 数据采集 菜单及其子菜单/按钮（如果前端已存在则更新/创建）
            data_parent, data_created = Menu.objects.get_or_create(name=DATA_COLLECT_PARENT_DEF["name"], defaults=DATA_COLLECT_PARENT_DEF)
            if not data_created:
                for k, v in DATA_COLLECT_PARENT_DEF.items():
                    setattr(data_parent, k, v)
                data_parent.save()

            # Create/update crawler children
            for item in CRAWLER_CHILD_DEFS:
                cm, c = Menu.objects.get_or_create(
                    name=item["name"], parent=data_parent,
                    defaults={
                        "type": 2,
                        "path": item["path"],
                        "component": item["component"],
                        "perms": item.get("perms", ""),
                        "icon": item.get("icon", ""),
                        "order_num": item.get("order_num", 0),
                        "visible": True,
                        "status": True,
                    }
                )
                if not c:
                    changed = False
                    for attr in ("path", "component", "perms", "icon", "order_num"):
                        new_val = item.get(attr)
                        if getattr(cm, attr) != new_val:
                            setattr(cm, attr, new_val)
                            changed = True
                    if changed:
                        cm.save()

                # Sync crawler-specific button permissions
                cb_defs = CRAWLER_BUTTON_DEFS.get(item["name"], [])
                for b in cb_defs:
                    cbm, created_btn = Menu.objects.get_or_create(
                        name=b["name"], parent=cm,
                        defaults={
                            "type": 3,
                            "path": "",
                            "component": "",
                            "perms": b.get("perms", ""),
                            "icon": "",
                            "order_num": b.get("order_num", 0),
                            "visible": True,
                            "status": True,
                        }
                    )
                    if not created_btn:
                        changed = False
                        if cbm.perms != b.get("perms", ""):
                            cbm.perms = b.get("perms", "")
                            changed = True
                        if cbm.order_num != b.get("order_num", 0):
                            cbm.order_num = b.get("order_num", 0)
                            changed = True
                        if changed:
                            cbm.save()

        # Bind all created/updated menus (parent and descendants) to admin role
        admin_role, _ = Role.objects.get_or_create(code="admin", defaults={"name": "管理员", "status": True})

        def collect_ids(node):
            ids = [node.id]
            for ch in Menu.objects.filter(parent=node):
                ids.extend(collect_ids(ch))
            return ids

        # Collect IDs from system parent and (if created) data_collect parent
        all_ids_set = set(collect_ids(parent))
        if 'data_parent' in locals():
            try:
                all_ids_set.update(collect_ids(data_parent))
            except Exception:
                pass
        all_ids = list(all_ids_set)
        if all_ids:
            admin_role.menus.add(*all_ids)

        self.stdout.write(self.style.SUCCESS(
            f"System menus synced. parent_created={created} children_created={created_children} children_updated={updated_children}"
        ))
