"""audit_orphans 管理命令

用途：在 SQLite（或其它数据库）环境下，对关键外键/多对多关系进行一次性数据审计，检测是否存在“孤立引用”。
范围：
- UserProfile.dept 是否指向不存在的 Department
- DictItem.dict_type 是否指向不存在的 DictType
- Role.menus（M2M）是否存在指向不存在的 Menu 的行（通过 through 表校验）
- AuthToken.user 是否指向不存在的 User

注意：不修改任何数据，仅输出报告，退出码总是 0。

执行：
    python manage.py audit_orphans
"""
from django.core.management.base import BaseCommand
from django.db import connection
from django.contrib.auth.models import User
from api_v1.models import Department, UserProfile, DictType, DictItem, Menu, Role, AuthToken


class Command(BaseCommand):
    help = "Audit orphaned foreign keys/m2m references and print a summary report"

    def handle(self, *args, **options):
        problems = []

        # 1) UserProfile.dept
        missing_dept_profiles = (
            UserProfile.objects.filter(dept_id__isnull=False)
            .exclude(dept_id__in=Department.objects.values_list("id", flat=True))
        )
        cnt1 = missing_dept_profiles.count()
        if cnt1:
            problems.append(("UserProfile.dept -> Department", cnt1))

        # 2) DictItem.dict_type
        missing_dt_items = (
            DictItem.objects.exclude(dict_type_id__in=DictType.objects.values_list("id", flat=True))
        )
        cnt2 = missing_dt_items.count()
        if cnt2:
            problems.append(("DictItem.dict_type -> DictType", cnt2))

        # 3) Role.menus through table
        through = Role.menus.through
        all_menu_ids = set(Menu.objects.values_list("id", flat=True))
        orphan_m2m = through.objects.exclude(menu_id__in=all_menu_ids)
        cnt3 = orphan_m2m.count()
        if cnt3:
            problems.append(("Role.menus -> Menu (through)", cnt3))

        # 4) AuthToken.user
        all_user_ids = set(User.objects.values_list("id", flat=True))
        cnt4 = AuthToken.objects.exclude(user_id__in=all_user_ids).count()
        if cnt4:
            problems.append(("AuthToken.user -> User", cnt4))

        # 输出报告
        if not problems:
            self.stdout.write(self.style.SUCCESS("No orphaned references detected."))
        else:
            self.stdout.write(self.style.WARNING("Detected orphaned references:"))
            for name, cnt in problems:
                self.stdout.write(f"  - {name}: {cnt}")
            self.stdout.write(self.style.WARNING("Consider writing a tailored cleanup command if needed."))

        # 附加：显示数据库外键约束是否启用（SQLite）
        try:
            if connection.vendor == "sqlite":
                cur = connection.cursor()
                cur.execute("PRAGMA foreign_keys;")
                row = cur.fetchone()
                fk_on = bool(row and row[0] == 1)
                self.stdout.write(f"SQLite PRAGMA foreign_keys = {'ON' if fk_on else 'OFF'}")
        except Exception:
            pass
