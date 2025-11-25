"""
api_v1 路由表

为了方便维护，所有路由均分段标注模块名，并映射到 `views.py` 中对应的 ViewSet 方法。
保持路径、方法与前端完全一致。
"""

from django.urls import path, re_path
from django.views.decorators.csrf import csrf_exempt
from . import views

urlpatterns = [
    # 认证模块
    path('auth/login', views.AuthViewSet.as_view({'post': 'login'}), name='auth-login'),
    path('auth/refresh-token', csrf_exempt(views.AuthViewSet.as_view({'post': 'refresh_token'})), name='auth-refresh'),
    path('auth/logout', views.AuthViewSet.as_view({'delete': 'logout', 'get': 'logout', 'post': 'logout'}), name='auth-logout'),
    path('auth/captcha', views.AuthViewSet.as_view({'get': 'captcha'}), name='auth-captcha'),

    # 文件管理模块已移除（文件上传/目录/分享/去重/哈希任务）。如需恢复请参考历史版本。

    # 代码生成
    path('codegen/table/page', views.CodegenViewSet.as_view({'get': 'table_page'}), name='codegen-table-page'),
    path('codegen/<str:table_name>/config', views.CodegenViewSet.as_view({'get': 'config', 'post': 'config', 'delete': 'config'}), name='codegen-config'),
    path('codegen/<str:table_name>/preview', views.CodegenViewSet.as_view({'get': 'preview'}), name='codegen-preview'),
    path('codegen/<str:table_name>/download', views.CodegenViewSet.as_view({'get': 'download'}), name='codegen-download'),

    # 用户模块（含手机号/邮箱绑定由 ProfileViewSet 提供）
    path('users/me', views.UserViewSet.as_view({'get': 'me'}), name='user-me'),
    path('users/page', views.UserViewSet.as_view({'get': 'page'}), name='user-page'),
    path('users/<str:user_id>/form', views.UserViewSet.as_view({'get': 'form'}), name='user-form'),
    # 将所有静态子路径放在 catch-all 之前，避免被 users/<str:id> 抢占
    path('users/template', views.UserViewSet.as_view({'get': 'template'}), name='user-template'),
    path('users/export', views.UserViewSet.as_view({'get': 'export'}), name='user-export'),
    path('users/import', views.UserViewSet.as_view({'post': 'import_users'}), name='user-import'),
    path('users/profile', views.UserViewSet.as_view({'get': 'profile_get', 'put': 'profile_put'}), name='user-profile'),
    path('users/password', views.UserViewSet.as_view({'put': 'change_password'}), name='user-change-password'),
    path('users/avatar', views.UserViewSet.as_view({'post': 'upload_avatar'}), name='user-upload-avatar'),
    path('users/upload-image', views.UserViewSet.as_view({'post': 'upload_image'}), name='user-upload-image'),
    # 静态子路径需置于 catch-all 之前
    path('users/options', views.UserViewSet.as_view({'get': 'options'}), name='user-options'),
    path('users/cloud-create', views.UserViewSet.as_view({'post': 'cloud_create'}), name='user-cloud-create'),
    # 列表/创建
    path('users', views.UserViewSet.as_view({'post': 'create', 'get': 'generic_get'}), name='users-create-or-template'),
    # 最后放置 catch-all 的单资源路径
    path('users/<str:id>', views.UserViewSet.as_view({'put': 'update', 'delete': 'delete'}), name='user-update-delete'),
    path('users/<str:id>/password/reset', views.UserViewSet.as_view({'put': 'reset_password'}), name='user-reset-password'),
    # DRF ViewSet for mobile/email code and binding with serializer validation
    path('users/mobile/code', views.ProfileViewSet.as_view({'post': 'send_mobile_code'}), name='user-mobile-code'),
    path('users/mobile', views.ProfileViewSet.as_view({'put': 'bind_mobile'}), name='user-bind-mobile'),
    path('users/email/code', views.ProfileViewSet.as_view({'post': 'send_email_code'}), name='user-email-code'),
    path('users/email', views.ProfileViewSet.as_view({'put': 'bind_email'}), name='user-bind-email'),
    # moved above

    # 角色模块（已接入 ORM）
    path('roles/page', views.RoleViewSet.as_view({'get': 'page'}), name='roles-page'),
    path('roles/options', views.RoleViewSet.as_view({'get': 'options'}), name='roles-options'),
    path('roles', views.RoleViewSet.as_view({'get': 'list_or_create', 'post': 'list_or_create'}), name='roles-list-create'),
    path('roles/<str:id>/form', views.RoleViewSet.as_view({'get': 'form'}), name='role-form'),
    path('roles/<str:ids>', views.RoleViewSet.as_view({'put': 'update_or_delete', 'delete': 'update_or_delete'}), name='role-update-delete'),
    path('roles/<str:role_id>/menuIds', views.RoleViewSet.as_view({'get': 'menu_ids'}), name='role-menu-ids'),
    path('roles/<str:role_id>/menus', views.RoleViewSet.as_view({'put': 'update_menus'}), name='role-update-menus'),

    # 通知公告
    path('notices/page', views.NoticeViewSet.as_view({'get': 'page'}), name='notices-page'),
    path('notices/<str:id>/form', views.NoticeViewSet.as_view({'get': 'form'}), name='notice-form'),
    path('notices/<str:id>/publish', views.NoticeViewSet.as_view({'post': 'publish'}), name='notice-publish'),
    path('notices/<str:id>/revoke', views.NoticeViewSet.as_view({'post': 'revoke'}), name='notice-revoke'),
    path('notices/<str:id>/read', views.NoticeViewSet.as_view({'post': 'read'}), name='notice-read'),
    path('notices/<str:id>/detail', views.NoticeViewSet.as_view({'get': 'detail_plain'}), name='notice-detail'),
    path('notices/read-all', views.NoticeViewSet.as_view({'post': 'read_all'}), name='notice-read-all'),
    path('notices/my-page', views.NoticeViewSet.as_view({'get': 'my_page'}), name='notices-my-page'),
    path('notices', views.NoticeViewSet.as_view({'get': 'list_or_create', 'post': 'list_or_create'}), name='notices-list-create'),
    path('notices/<str:ids>', views.NoticeViewSet.as_view({'put': 'update_or_delete', 'delete': 'update_or_delete'}), name='notice-update-delete'),

    # 菜单与动态路由
    path('menus/routes', views.MenuViewSet.as_view({'get': 'routes'}), name='menus-routes'),
    path('menus/tree', views.MenuViewSet.as_view({'get': 'tree'}), name='menus-tree'),
    path('menus', views.MenuViewSet.as_view({'get': 'list_or_create', 'post': 'list_or_create'}), name='menus-list-create'),
    path('menus/options', views.MenuViewSet.as_view({'get': 'options'}), name='menus-options'),
    path('menus/<str:id>/form', views.MenuViewSet.as_view({'get': 'form'}), name='menu-form'),
    path('menus/<str:id>', views.MenuViewSet.as_view({'put': 'update_or_delete', 'delete': 'update_or_delete'}), name='menu-update-delete'),

    # 数据采集节点（开放接口，无需认证）
    path('crawler/conf', views.CrawlerConfViewSet.as_view({'get': 'list_or_create', 'post': 'list_or_create'}), name='crawler-conf-list'),
    path('crawler/conf/<str:id>/form', views.CrawlerConfViewSet.as_view({'get': 'form'}), name='crawler-conf-form'),
    path('crawler/conf/<str:ids>', views.CrawlerConfViewSet.as_view({'put': 'update_or_delete', 'delete': 'update_or_delete'}), name='crawler-conf-update-delete'),
    # 爬虫日志（开放接口）：分页查询与写入
    path('crawler/logs/page', views.CrawlerLogViewSet.as_view({'get': 'page'}), name='crawler-logs-page'),
    path('crawler/logs', views.CrawlerLogViewSet.as_view({'get': 'list_or_create', 'post': 'list_or_create'}), name='crawler-logs-list-create'),

    # 爬取类目（分页公开，写入需认证）
    path('crawler/category/page', views.CrawlerCategoryViewSet.as_view({'get': 'page'}), name='crawler-category-page'),
    path('crawler/category/sites', views.CrawlerCategoryViewSet.as_view({'get': 'sites'}), name='crawler-category-sites'),
    path('crawler/category', views.CrawlerCategoryViewSet.as_view({'get': 'list_or_create', 'post': 'list_or_create'}), name='crawler-category-list'),
    path('crawler/category/<str:id>/form', views.CrawlerCategoryViewSet.as_view({'get': 'form'}), name='crawler-category-form'),
    path('crawler/category/<str:id>/times', views.CrawlerCategoryViewSet.as_view({'get': 'times'}), name='crawler-category-times'),
    path('crawler/category/<str:id>/file/check', views.CrawlerCategoryViewSet.as_view({'get': 'file_check'}), name='crawler-category-file-check'),
    path('crawler/category/<str:id>/file', views.CrawlerCategoryViewSet.as_view({'get': 'file'}), name='crawler-category-file'),
    path('crawler/category/<str:ids>', views.CrawlerCategoryViewSet.as_view({'put': 'update_or_delete', 'delete': 'update_or_delete'}), name='crawler-category-update-delete'),


    # 日志
    path('logs/page', views.LogViewSet.as_view({'get': 'page'}), name='logs-page'),
    path('logs/visit-trend', views.LogViewSet.as_view({'get': 'visit_trend'}), name='logs-visit-trend'),
    path('logs/visit-stats', views.LogViewSet.as_view({'get': 'visit_stats'}), name='logs-visit-stats'),

    # 字典与字典项
    path('dicts/page', views.DictViewSet.as_view({'get': 'page'}), name='dicts-page'),
    path('dicts', views.DictViewSet.as_view({'get': 'list_or_create', 'post': 'list_or_create'}), name='dicts-list-create'),
    path('dicts/<str:id>/form', views.DictViewSet.as_view({'get': 'form'}), name='dict-form'),
    path('dicts/<str:ids>', views.DictViewSet.as_view({'put': 'update_or_delete', 'delete': 'update_or_delete'}), name='dict-update-delete'),
    path('dicts/<str:dict_code>/items', views.DictViewSet.as_view({'get': 'items_list_or_create', 'post': 'items_list_or_create'}), name='dict-items-list-create'),
    path('dicts/<str:dict_code>/items/page', views.DictViewSet.as_view({'get': 'items_page'}), name='dict-items-page'),
    path('dicts/<str:dict_code>/items/<str:item_id>/form', views.DictViewSet.as_view({'get': 'item_form'}), name='dict-item-form'),

    # additional dict item routes for compatibility
    path('dicts/<str:dict_code>/items/options', views.DictViewSet.as_view({'get': 'item_options'}), name='dict-item-options'),
    path('dicts/<str:dict_code>/items/<str:item_id>', views.DictViewSet.as_view({'put': 'item_update_or_delete', 'delete': 'item_update_or_delete'}), name='dict-item-update-delete'),

    # 部门
    path('depts', views.DeptViewSet.as_view({'get': 'list_or_create', 'post': 'list_or_create'}), name='depts-list-create'),
    path('depts/tree', views.DeptViewSet.as_view({'get': 'tree'}), name='depts-tree'),
    path('depts/options', views.DeptViewSet.as_view({'get': 'options'}), name='depts-options'),
    path('depts/<str:id>/form', views.DeptViewSet.as_view({'get': 'form'}), name='dept-form'),
    path('depts/<str:ids>', views.DeptViewSet.as_view({'put': 'update_or_delete', 'delete': 'update_or_delete'}), name='dept-update-delete'),

    # 参数配置
    path('configs/page', views.ConfigViewSet.as_view({'get': 'page'}), name='configs-page'),
    path('configs', views.ConfigViewSet.as_view({'get': 'list_or_create', 'post': 'list_or_create'}), name='configs-list-create'),
    path('configs/<str:id>/form', views.ConfigViewSet.as_view({'get': 'form'}), name='config-form'),
    # 注意：将 refresh-cache 放在 catch-all 之前，避免被 <ids> 匹配导致 405
    path('configs/refresh-cache', views.ConfigViewSet.as_view({'post': 'refresh_cache'}), name='configs-refresh-cache'),
    path('configs/<str:ids>', views.ConfigViewSet.as_view({'put': 'update_or_delete', 'delete': 'update_or_delete'}), name='config-update-delete'),

    # 文件管理模块已彻底移除（相关路由和实现已删除）。

    # 根
    path('', views.root_index, name='api-root'),
]
