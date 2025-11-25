"""
api_v1 数据模型定义

说明：
- 为系统管理提供最小可用的数据结构：角色、部门、菜单、字典、配置、公告、日志、文件、用户扩展。
- 字段命名贴近前端需求；必要时增加唯一索引与排序字段。
- 后续可根据业务增加约束、索引与级联策略。
"""

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid


class TimeStampedModel(models.Model):
    """时间戳抽象基类：自动维护创建/更新时间"""
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class Role(TimeStampedModel):
    """角色表

    code: 角色编码，唯一
    name: 角色名称
    status: 是否启用
    remark: 备注
    order_num: 排序
    data_scope: 数据权限范围
        1 = 全部数据
        2 = 部门及子部门数据
        3 = 本部门数据
        4 = 本人数据
    """
    code = models.CharField(max_length=50, unique=True)
    name = models.CharField(max_length=50)
    status = models.BooleanField(default=True)
    remark = models.CharField(max_length=255, blank=True, default="")
    order_num = models.IntegerField(default=0)
    data_scope = models.IntegerField(default=1, help_text="1=全部数据 2=部门及子部门 3=本部门 4=本人")
    menus = models.ManyToManyField('Menu', blank=True, related_name='roles')

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = "角色"
        verbose_name_plural = "角色"
        ordering = ("order_num", "id")


class Department(TimeStampedModel):
    """部门表：父子树结构"""
    name = models.CharField(max_length=100)
    code = models.CharField(max_length=100, blank=True, default="", help_text="部门编号")
    parent = models.ForeignKey('self', null=True, blank=True, related_name='children', on_delete=models.SET_NULL)
    order_num = models.IntegerField(default=0)
    status = models.BooleanField(default=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = "部门"
        verbose_name_plural = "部门"
        ordering = ("order_num", "id")


class Menu(TimeStampedModel):
    MENU_TYPES = (
        (1, 'Directory'),
        (2, 'Menu'),
        (3, 'Button'),
        (4, 'External'),
    )
    name = models.CharField(max_length=100, help_text="菜单名称")
    parent = models.ForeignKey('self', null=True, blank=True, related_name='children', on_delete=models.SET_NULL)
    type = models.IntegerField(choices=MENU_TYPES, default=2)
    route_name = models.CharField(max_length=100, blank=True, default="", help_text="路由名称 name")
    path = models.CharField(max_length=200, blank=True, default="", help_text="路由路径")
    component = models.CharField(max_length=200, blank=True, default="", help_text="前端组件路径")
    perms = models.CharField(max_length=200, blank=True, default="", help_text="权限标识")
    icon = models.CharField(max_length=100, blank=True, default="", help_text="图标标识")
    order_num = models.IntegerField(default=0)
    visible = models.BooleanField(default=True)
    status = models.BooleanField(default=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = "菜单"
        verbose_name_plural = "菜单"
        ordering = ("order_num", "id")


class DictType(TimeStampedModel):
    """字典类型表"""
    code = models.CharField(max_length=50, unique=True)
    name = models.CharField(max_length=100)
    status = models.BooleanField(default=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = "字典类型"
        verbose_name_plural = "字典类型"


class DictItem(TimeStampedModel):
    """字典项表：同一字典下 value 唯一"""
    dict_type = models.ForeignKey(DictType, related_name='items', on_delete=models.CASCADE)
    label = models.CharField(max_length=100)
    value = models.CharField(max_length=100)
    sort = models.IntegerField(default=0)
    status = models.BooleanField(default=True)
    # 标签类型（Element Plus Tag type），用于前端渲染样式，可为空
    tag_type = models.CharField(max_length=20, blank=True, default="")

    class Meta:
        unique_together = (('dict_type', 'value'),)

    def __str__(self):
        return f"{self.dict_type.code}:{self.label}"

    class Meta:
        verbose_name = "字典项"
        verbose_name_plural = "字典项"
        ordering = ("sort", "id")


class Config(TimeStampedModel):
    """系统参数配置"""
    key = models.CharField(max_length=100, unique=True)
    value = models.TextField(blank=True, default="")
    remark = models.CharField(max_length=255, blank=True, default="")
    status = models.BooleanField(default=True)

    def __str__(self):
        return self.key

    class Meta:
        verbose_name = "系统参数"
        verbose_name_plural = "系统参数"


class Notice(TimeStampedModel):
    """通知公告"""
    title = models.CharField(max_length=200)
    content = models.TextField(blank=True, default="")
    type = models.CharField(max_length=50, blank=True, default="general")
    status = models.CharField(max_length=20, default='draft')  # draft/published/revoked
    publish_time = models.DateTimeField(null=True, blank=True)
    revoke_time = models.DateTimeField(null=True, blank=True)
    creator = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)

    def __str__(self):
        return self.title

    class Meta:
        verbose_name = "通知公告"
        verbose_name_plural = "通知公告"


class OperLog(TimeStampedModel):
    """操作日志"""
    module = models.CharField(max_length=100)
    action = models.CharField(max_length=100)
    operator = models.CharField(max_length=100, blank=True, default="")
    ip = models.CharField(max_length=45, blank=True, default="")
    user_agent = models.CharField(max_length=255, blank=True, default="")
    result = models.CharField(max_length=20, default='success')
    elapsed_ms = models.IntegerField(default=0)

    class Meta:
        verbose_name = "操作日志"
        verbose_name_plural = "操作日志"
        ordering = ("-id",)


class CrawlerLog(TimeStampedModel):
    """爬虫专用日志表（与系统操作日志分离）

    字段说明：
    - module: 日志来源模块
    - content: 日志内容/消息
    - level: 日志级别（debug/info/warn/error）
    - elapsed_ms: 模块耗时（毫秒）
    - operator/ip/user_agent: 可选上下文信息
    """
    LEVEL_CHOICES = (
        ("debug", "debug"),
        ("info", "info"),
        ("warn", "warn"),
        ("error", "error"),
    )

    module = models.CharField(max_length=100, blank=True, default="")
    content = models.TextField(blank=True, default="")
    level = models.CharField(max_length=10, choices=LEVEL_CHOICES, default="info")
    elapsed_ms = models.IntegerField(default=0)
    operator = models.CharField(max_length=100, blank=True, default="")
    ip = models.CharField(max_length=45, blank=True, default="")
    user_agent = models.CharField(max_length=255, blank=True, default="")

    class Meta:
        verbose_name = "爬虫日志"
        verbose_name_plural = "爬虫日志"
        ordering = ("-id",)




class UserProfile(TimeStampedModel):
    """用户扩展信息（不替换内置 User，避免迁移复杂度）"""
    user = models.OneToOneField(User, related_name='profile', on_delete=models.CASCADE)
    nickname = models.CharField(max_length=100, blank=True, default="")
    mobile = models.CharField(max_length=20, blank=True, default="")
    avatar = models.CharField(max_length=255, blank=True, default="")
    # cloud_id: 存储第三方 Seafile 返回的标识（例如 account email/ID），用于后续同步删除
    cloud_id = models.CharField(max_length=255, blank=True, default="")
    dept = models.ForeignKey('Department', null=True, blank=True, on_delete=models.SET_NULL)
    gender = models.IntegerField(default=0, help_text="0=保密,1=男,2=女")

    roles = models.ManyToManyField(Role, blank=True, related_name='users')

    class Meta:
        verbose_name = "用户扩展"
        verbose_name_plural = "用户扩展"


class AuthToken(TimeStampedModel):
    """简单的访问/刷新令牌"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tokens')
    access_token = models.CharField(max_length=200, unique=True)
    refresh_token = models.CharField(max_length=200, unique=True)
    access_expires_at = models.DateTimeField()
    refresh_expires_at = models.DateTimeField()
    revoked = models.BooleanField(default=False)

    def is_access_valid(self):
        return (not self.revoked) and timezone.now() < self.access_expires_at

    def is_refresh_valid(self):
        return (not self.revoked) and timezone.now() < self.refresh_expires_at

    class Meta:
        verbose_name = "认证令牌"
        verbose_name_plural = "认证令牌"
        indexes = [
            models.Index(fields=["access_token"]),
            models.Index(fields=["refresh_token"]),
        ]


class CloudAuthToken(TimeStampedModel):
    """缓存 Seafile cloud token（临时）

    说明：用于在用户登录后，后端使用该用户凭据向 Seafile 获取 token 并缓存，
    仅用于后端对 Seafile 的短期代理请求。前端**不**直接使用此 token。
    """
    user = models.OneToOneField(User, related_name='cloud_token', on_delete=models.CASCADE)
    site = models.CharField(max_length=255, blank=True, default="")
    token = models.CharField(max_length=255, blank=True, default="")
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "云认证令牌"
        verbose_name_plural = "云认证令牌"


class NoticeRead(TimeStampedModel):
    """用户-公告已读记录

    用于记录某用户已读的公告，前端展示“我的公告/未读”时可以排除已读项。
    """
    user = models.ForeignKey(User, related_name='notice_reads', on_delete=models.CASCADE)
    notice = models.ForeignKey(Notice, related_name='reads', on_delete=models.CASCADE)
    read_at = models.DateTimeField(default=timezone.now)

    class Meta:
        verbose_name = "公告已读"
        verbose_name_plural = "公告已读"
        unique_together = (('user', 'notice'),)


class CrawlerConf(TimeStampedModel):
    """数据采集节点配置

    前端使用字段名：server_name, node, ip, status, order_num
    该模型用于记录可公开访问的爬取节点配置（开放接口，无需认证）
    """
    server_name = models.CharField(max_length=200)
    node = models.CharField(max_length=200)
    ip = models.CharField(max_length=100, blank=True, default="")
    status = models.IntegerField(default=1)
    order_num = models.IntegerField(default=0)

    class Meta:
        verbose_name = "数据采集节点"
        verbose_name_plural = "数据采集节点"
        ordering = ("order_num", "id")


class CrawlerCategory(TimeStampedModel):
    """爬取类目表

    前端字段名映射：name, category_id, site, category_type, status
    """
    name = models.CharField(max_length=200)
    category_id = models.CharField(max_length=200, blank=True, default="")
    site = models.CharField(max_length=100, blank=True, default="")
    category_type = models.CharField(max_length=100, blank=True, default="")
    status = models.IntegerField(default=1)

    class Meta:
        verbose_name = "爬取类目"
        verbose_name_plural = "爬取类目"
        ordering = ("-created_at", "id")


# ---------------- 文件管理微模块模型（最小可用） -----------------
class FileFolder(TimeStampedModel):
    """文件夹

    使用 external_id 与前端传入的 fileId/hash 保持对应，避免与内部主键耦合。
    根目录以 parent=None 表示；逻辑删除采用 is_deleted + deleted_at。
    """
    external_id = models.CharField(max_length=64, unique=True, help_text="前端生成的文件夹ID")
    name = models.CharField(max_length=255)
    parent = models.ForeignKey('self', null=True, blank=True, related_name='children', on_delete=models.SET_NULL)
    owner = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "文件夹"
        verbose_name_plural = "文件夹"
        indexes = [
            models.Index(fields=["external_id"]),
            models.Index(fields=["is_deleted"]),
        ]

    def __str__(self):
        return self.name


class FileAsset(TimeStampedModel):
    """合并后的文件（逻辑文件）

    file_id: 前端生成的文件ID（区分于数据库主键）
    merge_file_id: 分片阶段生成的临时合并ID (pid) — 便于前端把每个分片与目标文件关联。
    file_hash: 整体文件哈希（用于秒传/断点续传判断）
    total_chunks / uploaded_chunks: 分片计数与进度
    is_completed: 是否已全部分片上传合并
    storage_path: 完整文件或合并后文件的实际存储路径（当前阶段占位，可为最后一个分片路径）
    """
    file_id = models.CharField(max_length=64, unique=True, help_text="前端生成的文件ID")
    merge_file_id = models.CharField(max_length=64, unique=True, help_text="分片阶段合并文件ID")
    name = models.CharField(max_length=255)
    size = models.BigIntegerField(default=0)
    file_hash = models.CharField(max_length=128, db_index=True)
    ext = models.CharField(max_length=50, blank=True, default="")
    mime_type = models.CharField(max_length=100, blank=True, default="")
    folder = models.ForeignKey(FileFolder, null=True, blank=True, related_name='assets', on_delete=models.SET_NULL)
    owner = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    total_chunks = models.IntegerField(default=0)
    uploaded_chunks = models.IntegerField(default=0)
    is_completed = models.BooleanField(default=False)
    storage_path = models.CharField(max_length=255, blank=True, default="")
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "文件"
        verbose_name_plural = "文件"
        indexes = [
            models.Index(fields=["file_hash"]),
            models.Index(fields=["is_deleted", "is_completed"]),
        ]

    def __str__(self):
        return self.name


class FileChunk(TimeStampedModel):
    """文件分片记录

    chunk_hash: 单个分片哈希，用于断点续传去重。
    num: 分片序号（从0开始）
    storage_path: 分片物理存储相对路径
    """
    asset = models.ForeignKey(FileAsset, related_name='chunks', on_delete=models.CASCADE)
    chunk_hash = models.CharField(max_length=128, db_index=True)
    num = models.IntegerField()
    size = models.BigIntegerField(default=0)
    storage_path = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "文件分片"
        verbose_name_plural = "文件分片"
        unique_together = ("asset", "num")
        indexes = [
            models.Index(fields=["chunk_hash"]),
        ]

    def __str__(self):
        return f"{self.asset_id}:{self.num}"

