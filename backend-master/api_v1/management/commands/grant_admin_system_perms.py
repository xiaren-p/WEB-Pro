"""grant_admin_system_perms 管理命令

为 admin 角色与 admin 用户授予“系统管理”菜单下的全部权限：
- 将“系统管理”父菜单及其子菜单全部绑定到 admin 角色
- 确保 admin 用户存在 profile 并加入 admin 角色
- 若不存在“系统管理”菜单，仅绑定当前已有的同名父菜单或忽略

执行：
    python manage.py grant_admin_system_perms
"""
from django.core.management.base import BaseCommand
from django.db import transaction
from django.contrib.auth.models import User
from api_v1.models import Role, Menu, UserProfile


class Command(BaseCommand):
    help = "Grant all system management permissions to admin role and user"

    @transaction.atomic
    def handle(self, *args, **options):
        # 确保 admin 角色存在
        admin_role, _ = Role.objects.get_or_create(code='admin', defaults={'name': '管理员', 'status': True})

        # 查找系统管理菜单
        system_parent = Menu.objects.filter(name='系统管理').first()
        if system_parent:
            # 绑定父与所有子菜单
            child_ids = list(Menu.objects.filter(parent=system_parent).values_list('id', flat=True))
            bind_ids = [system_parent.id] + child_ids
            admin_role.menus.add(*bind_ids)
            self.stdout.write(self.style.SUCCESS(f"Bound {len(bind_ids)} system menus to admin role."))
        else:
            self.stdout.write(self.style.WARNING("No '系统管理' menu found. Skipped menus binding."))

        # 绑定 admin 用户
        admin_user = User.objects.filter(username='admin').first()
        if not admin_user:
            self.stdout.write(self.style.WARNING("No user 'admin' found. Only role updated."))
            return
        profile = getattr(admin_user, 'profile', None)
        if not profile:
            profile = UserProfile.objects.create(user=admin_user, nickname='管理员')
        profile.roles.add(admin_role)
        self.stdout.write(self.style.SUCCESS("Admin user bound to admin role."))
