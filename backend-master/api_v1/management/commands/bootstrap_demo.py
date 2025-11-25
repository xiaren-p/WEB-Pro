"""bootstrap_demo 管理命令：初始化最小演示数据

执行：python manage.py bootstrap_demo
内容：
- 创建 admin 角色（code=admin）
- 创建基础菜单：仪表盘、系统管理（父）、角色管理（含 perms 示例 system:role:edit）
- 创建一个部门（总公司）
- 创建超级用户 admin（若不存在）并绑定 UserProfile、分配角色

幂等：重复执行不报错，已有对象跳过。
"""
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from api_v1.models import Role, Menu, Department, UserProfile

class Command(BaseCommand):
    help = 'Initialize demo data (roles, menus, department, admin user)'

    def handle(self, *args, **options):
        # Role
        admin_role, _ = Role.objects.get_or_create(code='admin', defaults={'name': '管理员', 'status': True})

        # Menus
        dashboard_menu, _ = Menu.objects.get_or_create(name='仪表盘', defaults={'type': 2, 'path': '/dashboard', 'component': 'dashboard/index', 'order_num': 1})
        system_root, _ = Menu.objects.get_or_create(name='系统管理', defaults={'type': 1, 'path': '/system', 'component': 'Layout', 'order_num': 10})
        role_menu, _ = Menu.objects.get_or_create(name='角色管理', defaults={'type': 2, 'parent': system_root, 'path': '/system/role', 'component': 'system/role/index', 'perms': 'system:role:edit', 'order_num': 11})

        # Attach menus to role (ensure all three)
        admin_role.menus.add(dashboard_menu, system_root, role_menu)

        # Department
        root_dept, _ = Department.objects.get_or_create(name='总公司', defaults={'order_num': 1, 'status': True})

        # User & profile
        admin_user = User.objects.filter(username='admin').first()
        if not admin_user:
            admin_user = User.objects.create_superuser('admin', 'admin@example.com', 'admin123')
            self.stdout.write(self.style.SUCCESS('Created superuser admin (password: admin123)'))
        profile = getattr(admin_user, 'profile', None)
        if not profile:
            profile = UserProfile.objects.create(user=admin_user, nickname='管理员', dept=root_dept)
        # Bind role
        profile.roles.add(admin_role)

        self.stdout.write(self.style.SUCCESS('Demo data initialized.'))
