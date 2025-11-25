"""purge_file_module_artifacts 管理命令

用途：一次性清理已经下线的“文件管理”模块在数据库中可能残留的：
- 菜单(Menu) 记录：名称/路径/组件/权限包含文件管理标识（sys:file:*）
- 角色(Role).menus 关系中指向上述菜单的关联
- 操作日志(OperLog) 中 module='文件' / '文件管理' 的旧记录（可选）

默认仅执行菜单与关系清理；如需同时删除旧日志，添加 --with-logs。

执行示例：
    python manage.py purge_file_module_artifacts --with-logs

幂等：可重复执行；找不到目标数据时安全退出。
"""
from django.core.management.base import BaseCommand
from django.db import transaction
from django.db.models import Q
from api_v1.models import Menu, Role, OperLog


class Command(BaseCommand):
    help = "Purge legacy file module menus (and optionally logs) after module decommission"

    def add_arguments(self, parser):
        parser.add_argument(
            "--with-logs",
            action="store_true",
            help="Also delete OperLog rows whose module looks like file module history (module in ['文件','文件管理'] or action contains '文件')",
        )

    @transaction.atomic
    def handle(self, *args, **options):
        with_logs = options.get("with_logs")
        # 1. Locate candidate menus (self + descendants) to delete
        roots = list(
            Menu.objects.filter(
                Q(name="文件管理") | Q(path="/system/file") | Q(component__icontains="system/file") | Q(perms__startswith="sys:file:")
            )
        )
        # Include any buttons under those roots even if they themselves do not match the Q above (defensive)
        target_ids = set()
        def collect(menu):
            if menu.id in target_ids:
                return
            target_ids.add(menu.id)
            for ch in Menu.objects.filter(parent=menu):
                collect(ch)
        for r in roots:
            collect(r)
        deleted_menu_count = 0
        if target_ids:
            # Remove M2M relations first (Django will cascade, but clearing improves clarity for output)
            roles = Role.objects.filter(menus__id__in=target_ids).distinct()
            affected_role_count = roles.count()
            for role in roles:
                role.menus.remove(*list(target_ids))
            deleted_menu_count, _ = Menu.objects.filter(id__in=target_ids).delete()
        else:
            affected_role_count = 0
        # 2. Optionally delete old logs
        deleted_log_count = 0
        if with_logs:
            log_qs = OperLog.objects.filter(Q(module__in=["文件", "文件管理"]) | Q(action__icontains="文件"))
            deleted_log_count, _ = log_qs.delete()
        self.stdout.write(
            self.style.SUCCESS(
                f"purge complete: menus_deleted={deleted_menu_count} roles_affected={affected_role_count} logs_deleted={deleted_log_count}"
            )
        )
