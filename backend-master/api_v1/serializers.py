"""
api_v1 序列化器

集中放置 DRF 序列化器，供 views 引用，减少 views.py 体积并规范字段别名映射。
"""

from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Role, Department, DictType, DictItem, Config, Notice, UserProfile, Menu, OperLog
from .models import CrawlerLog
from .models import CrawlerConf
from .models import CrawlerCategory
import re


class RoleSerializer(serializers.ModelSerializer):
    # 前端字段别名：sort <-> order_num
    sort = serializers.IntegerField(source="order_num")
    status = serializers.SerializerMethodField()
    dataScope = serializers.IntegerField(source="data_scope")

    def get_status(self, obj):
        return 1 if obj.status else 0

    class Meta:
        model = Role
        fields = ["id", "code", "name", "status", "remark", "sort", "dataScope", "created_at", "updated_at"]


class RoleWriteSerializer(serializers.ModelSerializer):
    sort = serializers.IntegerField(source="order_num", required=False)
    status = serializers.IntegerField(required=False)
    dataScope = serializers.IntegerField(source="data_scope", required=False)

    def validate_status(self, value):
        # 将 1/0 转换为布尔
        return bool(int(value))

    class Meta:
        model = Role
        fields = ["code", "name", "remark", "sort", "status", "dataScope"]


class DeptSerializer(serializers.ModelSerializer):
    parentId = serializers.IntegerField(source="parent_id", allow_null=True, required=False)
    sort = serializers.IntegerField(source="order_num")
    code = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = Department
        fields = ["id", "name", "code", "status", "parentId", "sort"]


class MenuSerializer(serializers.ModelSerializer):
    parentId = serializers.IntegerField(source="parent_id", allow_null=True, required=False)
    sort = serializers.IntegerField(source="order_num", required=False)
    visible = serializers.IntegerField(source="visible", required=False)
    status = serializers.IntegerField(source="status", required=False)
    routeName = serializers.CharField(source="route_name", required=False, allow_blank=True)

    class Meta:
        model = Menu
        fields = [
            "id", "name", "type", "routeName", "path", "component", "perms", "icon",
            "parentId", "sort", "visible", "status"
        ]


class OperLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = OperLog
        fields = [
            "id", "module", "action", "operator", "ip", "user_agent", "result", "elapsed_ms", "created_at"
        ]


class CrawlerLogSerializer(serializers.ModelSerializer):
    # level 允许预定义的日志级别
    level = serializers.ChoiceField(choices=["debug", "info", "warn", "error"], required=False)

    class Meta:
        model = CrawlerLog
        fields = [
            "id", "module", "content", "level", "elapsed_ms", "operator", "ip", "user_agent", "created_at",
        ]

    def validate_level(self, value):
        if not value:
            return "info"
        return value

    def validate_elapsed_ms(self, value):
        try:
            return int(value or 0)
        except Exception:
            raise serializers.ValidationError("elapsed_ms must be integer")


## 文件管理序列化器已移除（FileObjectSerializer, FileEntrySerializer）


class UserSerializer(serializers.ModelSerializer):
    nickname = serializers.CharField(source="profile.nickname", allow_blank=True, default="")
    mobile = serializers.CharField(source="profile.mobile", allow_blank=True, default="")
    avatar = serializers.CharField(source="profile.avatar", allow_blank=True, default="")
    cloudId = serializers.CharField(source="profile.cloud_id", allow_blank=True, default="")
    deptId = serializers.IntegerField(source="profile.dept_id", allow_null=True, default=None)
    roleIds = serializers.SerializerMethodField()
    gender = serializers.SerializerMethodField()
    deptName = serializers.SerializerMethodField()
    roleNames = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    createTime = serializers.DateTimeField(source="date_joined", format="%Y-%m-%d %H:%M:%S", read_only=True)

    def get_roleIds(self, obj):
        if hasattr(obj, "profile"):
            return list(obj.profile.roles.values_list("id", flat=True))
        return []

    def get_gender(self, obj):
        # 暂无 gender 字段，预留：可在 UserProfile 增加 gender(int)；当前返回 None 兼容前端
        return getattr(getattr(obj, 'profile', None), 'gender', None)

    def get_deptName(self, obj):
        profile = getattr(obj, 'profile', None)
        if profile and profile.dept:
            return profile.dept.name
        return ""

    def get_roleNames(self, obj):
        profile = getattr(obj, 'profile', None)
        if profile:
            return ",".join(profile.roles.values_list('name', flat=True))
        return ""

    def get_status(self, obj):
        return 1 if obj.is_active else 0

    class Meta:
        model = User
        fields = [
            "id", "username", "nickname", "mobile", "avatar", "email",
            "deptId", "deptName", "roleIds", "roleNames", "gender", "status", "createTime",
            "cloudId"
        ]


class DictTypeSerializer(serializers.ModelSerializer):
    dictCode = serializers.CharField(source="code")

    class Meta:
        model = DictType
        fields = ["id", "name", "dictCode", "status"]


class DictItemSerializer(serializers.ModelSerializer):
    # 将布尔 status 统一转换为数字 1/0，前端使用严格比较 === 1
    status = serializers.SerializerMethodField()
    # 标签类型字段：数据库字段 tag_type <-> 前端字段 tagType
    tagType = serializers.CharField(source="tag_type", required=False, allow_blank=True)

    def get_status(self, obj):  # noqa: D401
        return 1 if obj.status else 0

    class Meta:
        model = DictItem
        fields = ["id", "label", "value", "sort", "status", "tagType"]


class ConfigSerializer(serializers.ModelSerializer):
    configName = serializers.CharField(source="key")
    configKey = serializers.CharField(source="key")
    configValue = serializers.CharField(source="value")

    class Meta:
        model = Config
        fields = ["id", "configName", "configKey", "configValue", "status", "remark"]


class NoticeBriefSerializer(serializers.ModelSerializer):
    publishStatus = serializers.SerializerMethodField()
    publisherName = serializers.SerializerMethodField()
    publishTime = serializers.SerializerMethodField()
    revokeTime = serializers.SerializerMethodField()
    createTime = serializers.DateTimeField(source="created_at", format="%Y-%m-%d %H:%M:%S", read_only=True)

    def get_publishStatus(self, obj: Notice):
        # 前端规范：0=未发布, 1=已发布, -1=已撤回
        return 1 if obj.status == 'published' else (-1 if obj.status == 'revoked' else 0)

    def get_publisherName(self, obj: Notice):
        return getattr(obj.creator, 'username', '')

    def get_publishTime(self, obj: Notice):
        return obj.publish_time.strftime("%Y-%m-%d %H:%M:%S") if obj.publish_time else None

    def get_revokeTime(self, obj: Notice):
        return obj.revoke_time.strftime("%Y-%m-%d %H:%M:%S") if obj.revoke_time else None

    class Meta:
        model = Notice
        fields = [
            "id", "title", "type", "publishStatus", "publisherName", "publishTime", "revokeTime", "createTime", "status"
        ]


class NoticeDetailSerializer(NoticeBriefSerializer):
    class Meta(NoticeBriefSerializer.Meta):
        fields = NoticeBriefSerializer.Meta.fields + ["content"]

# ---- Simple bind/code serializers ----
MOBILE_REGEX = re.compile(r"^1[3-9]\d{9}$")


class MobileCodeSendSerializer(serializers.Serializer):
    mobile = serializers.CharField(max_length=20)

    def validate_mobile(self, value: str) -> str:
        if not MOBILE_REGEX.match(value):
            raise serializers.ValidationError("手机号格式不正确")
        return value


class MobileBindSerializer(serializers.Serializer):
    mobile = serializers.CharField(max_length=20)
    code = serializers.CharField(max_length=10)

    def validate_mobile(self, value: str) -> str:
        if not MOBILE_REGEX.match(value):
            raise serializers.ValidationError("手机号格式不正确")
        return value


class EmailCodeSendSerializer(serializers.Serializer):
    email = serializers.EmailField()


class EmailBindSerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(max_length=10)


class CrawlerConfSerializer(serializers.ModelSerializer):
    class Meta:
        model = CrawlerConf
        fields = ["id", "server_name", "node", "ip", "status", "order_num", "created_at", "updated_at"]


class CrawlerCategorySerializer(serializers.ModelSerializer):
    # 前端使用小写下划线字段名与模型一致
    class Meta:
        model = CrawlerCategory
        fields = ["id", "name", "category_id", "site", "category_type", "status", "created_at", "updated_at"]

