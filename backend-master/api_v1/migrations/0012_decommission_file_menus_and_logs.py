from django.db import migrations, models
from django.db.models import Q


def drop_file_menus(apps, schema_editor):
    Menu = apps.get_model('api_v1', 'Menu')
    # 删除名称/路径/组件/权限匹配文件模块特征的菜单（包含按钮权限）
    qs = Menu.objects.filter(
        Q(name='文件管理') | Q(path='/system/file') | Q(component__icontains='system/file') | Q(perms__startswith='sys:file:')
    )
    # 兼容：若“文件管理”目录仍存在，递归删除其子节点
    targets = list(qs)
    target_ids = set()
    def collect(menu):
        if menu.id in target_ids:
            return
        target_ids.add(menu.id)
        for ch in Menu.objects.filter(parent_id=menu.id):
            collect(ch)
    for m in targets:
        collect(m)
    if target_ids:
        Menu.objects.filter(id__in=list(target_ids)).delete()


def purge_file_logs(apps, schema_editor):
    OperLog = apps.get_model('api_v1', 'OperLog')
    try:
        OperLog.objects.filter(Q(module__in=['文件', '文件管理']) | Q(action__icontains='文件')).delete()
    except Exception:
        # 忽略清理失败（不同环境可能不存在这些数据）
        pass


class Migration(migrations.Migration):
    dependencies = [
        ('api_v1', '0011_remove_hashtask_entry_remove_hashtask_parent_and_more'),
    ]

    operations = [
        migrations.RunPython(drop_file_menus, reverse_code=migrations.RunPython.noop),
        migrations.RunPython(purge_file_logs, reverse_code=migrations.RunPython.noop),
    ]
