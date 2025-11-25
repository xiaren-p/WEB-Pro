# 文件管理视图及 ACL/分享相关辅助端点已彻底移除。
from PIL import Image
from django.contrib.auth import authenticate
# 通用依赖导入（被此前大规模清理影响，这里补齐）
from django.http import HttpResponse
from django.db.models import Q
from django.contrib.auth.models import User
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAuthenticated

from .models import (
    Role, Department, DictType, DictItem, Config, Notice, Menu, OperLog, UserProfile, CrawlerConf,
)
from .serializers import (
    RoleSerializer, RoleWriteSerializer, DeptSerializer, MenuSerializer, OperLogSerializer, UserSerializer,
    DictTypeSerializer, DictItemSerializer, ConfigSerializer, NoticeBriefSerializer, NoticeDetailSerializer,
    MobileCodeSendSerializer, MobileBindSerializer, EmailCodeSendSerializer, EmailBindSerializer,
    CrawlerConfSerializer,
)
from .serializers import CrawlerLogSerializer
from .models import CrawlerCategory
from .serializers import CrawlerCategorySerializer
from .utils.responses import drf_ok, drf_error
from .utils.pagination import paginate_queryset
from .permissions import MenuPermRequired
from .utils.oplog import write_log
from .utils.captcha import generate_captcha
from django.utils import timezone
from django.conf import settings
import uuid
from .models import AuthToken
import requests
import json
import re
from urllib.parse import quote
from django.core.files.storage import default_storage
import os


class AuthViewSet(viewsets.ViewSet):
    """身份认证相关接口（登录/登出/刷新 token 等）"""
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        action = getattr(self, 'action', None)
        # 允许匿名访问的动作：登录、图形验证码、刷新 token（刷新 token 使用 refreshToken 字段）
        if action in ("login", "captcha", "refresh_token"):
            return [AllowAny()]
        return super().get_permissions()

    @action(detail=False, methods=["post"], url_path="login")
    def login(self, request):  # pragma: no cover
        t0 = timezone.now()
        username = (request.data or {}).get('username')
        password = (request.data or {}).get('password')
        if not username or not password:
            return drf_error("用户名或密码不能为空", status=400)

        # 校验账号密码
        user = authenticate(username=username, password=password)
        if not user:
            return drf_error("用户名或密码错误", status=401)

        # 生成 access / refresh token
        access_ttl = getattr(settings, 'ACCESS_TOKEN_EXPIRE_SECONDS', 86400)
        refresh_ttl = getattr(settings, 'REFRESH_TOKEN_EXPIRE_SECONDS', 7 * 86400)
        at = AuthToken.objects.create(
            user=user,
            access_token=uuid.uuid4().hex,
            refresh_token=uuid.uuid4().hex,
            access_expires_at=timezone.now() + timezone.timedelta(seconds=access_ttl),
            refresh_expires_at=timezone.now() + timezone.timedelta(seconds=refresh_ttl),
        )

        # 尝试读取字典以获取 Seafile site 并用当前登录密码去获取 token（登录时提供的密码即系统密码）
        seafile_cached = {"cached": False}
        try:
            site = None
            try:
                items = list(DictItem.objects.filter(dict_type__code__in=["cloud_type", "clooud_type"], status=True))
                if items:
                    for it in items:
                        label = (it.label or "").lower()
                        val = (it.value or "").strip()
                        if not site and ("site" in label or "站" in label or val.startswith("http")):
                            site = val
                            break
                    if (not site) and items[0] and items[0].value:
                        try:
                            j = json.loads(items[0].value)
                            site = site or j.get("site") or j.get("url") or j.get("host") or j.get("endpoint")
                        except Exception:
                            pass
            except Exception:
                site = None

            if site:
                try:
                    from .utils.seafile import fetch_token_by_credentials, cache_token_for_user
                    token, err = fetch_token_by_credentials(site, username, password)
                    if token:
                        # 登录时使用的密码即系统密码，安全写入缓存
                        try:
                            cache_token_for_user(user, site, token)
                            seafile_cached = {"cached": True, "msg": "cached"}
                        except Exception:
                            seafile_cached = {"cached": False, "msg": "cache failed"}
                    else:
                        seafile_cached = {"cached": False, "msg": err or "no token"}
                except Exception as e:
                    seafile_cached = {"cached": False, "msg": f"seafile request error: {e}"}
            else:
                seafile_cached = {"cached": False, "msg": "no site configured"}
        except Exception:
            seafile_cached = {"cached": False, "msg": "exception"}

        write_log(request, module='Auth', action=f'用户登录：{username}', result='success', elapsed_ms=0)
        resp = {
            "accessToken": at.access_token,
            "refreshToken": at.refresh_token,
            "tokenType": "Bearer",
            "expiresIn": access_ttl,
        }
        try:
            resp["seafileCached"] = bool(seafile_cached.get("cached", False)) if isinstance(seafile_cached, dict) else bool(seafile_cached)
            resp["seafileCachedDetail"] = seafile_cached
        except Exception:
            resp["seafileCached"] = False
            resp["seafileCachedDetail"] = {"cached": False}
        return drf_ok(resp)

    from django.views.decorators.csrf import csrf_exempt
    @csrf_exempt
    @action(detail=False, methods=["post"], url_path="refresh-token")
    def refresh_token(self, request):  # pragma: no cover
        token = request.query_params.get('refreshToken') or (request.data or {}).get('refreshToken')
        if not token:
            return drf_error("缺少 refreshToken", status=400)
        try:
            obj = AuthToken.objects.get(refresh_token=token, revoked=False)
        except AuthToken.DoesNotExist:
            return drf_error("刷新令牌无效", status=401)
        if not obj.is_refresh_valid():
            return drf_error("刷新令牌已过期", status=401)
        # 生成新的 access token（不旋转 refresh）
        access_ttl = getattr(settings, 'ACCESS_TOKEN_EXPIRE_SECONDS', 86400)
        obj.access_token = uuid.uuid4().hex
        obj.access_expires_at = timezone.now() + timezone.timedelta(seconds=access_ttl)
        obj.save(update_fields=["access_token", "access_expires_at", "updated_at"])
        write_log(request, module='Auth', action='刷新令牌', result='success', elapsed_ms=0)
        return drf_ok({
            "accessToken": obj.access_token,
            "tokenType": "Bearer",
            "expiresIn": access_ttl,
        })

    @action(detail=False, methods=["delete", "get", "post"], url_path="logout")
    def logout(self, request):  # pragma: no cover
        # 从 Authorization 提取当前 access token 并撤销
        try:
            from rest_framework.authentication import get_authorization_header
            parts = get_authorization_header(request).split()
            if parts and len(parts) == 2 and parts[0].lower() == b"bearer":
                tok = parts[1].decode()
                AuthToken.objects.filter(access_token=tok, revoked=False).update(revoked=True)
        except Exception:
            pass
        write_log(request, module='Auth', action='退出登录', result='success', elapsed_ms=0)
        return drf_ok(status=204)

    @action(detail=False, methods=["get"], url_path="captcha")
    def captcha(self, request):  # pragma: no cover
        # 生成图形验证码（若 PIL 不可用，回退为透明 1x1 PNG）
        key, img_b64, _text = generate_captcha()
        return drf_ok({"img": img_b64, "uuid": key})


# --- Users & Profile ---
class UserViewSet(viewsets.ViewSet):
    """用户相关接口

    路由前缀：/users
    支持：分页、详情、创建、更新、删除、导入导出、密码修改/重置、个人资料、下拉选项
    """

    from django.views.decorators.csrf import csrf_exempt
    @csrf_exempt
    @action(detail=False, methods=["get"], url_path="me")
    def me(self, request):
        import time
        t0 = time.perf_counter()
        user = request.user
        if not user.is_authenticated:
            write_log(request, module='User', action='获取当前用户信息失败：未登录', result='fail', elapsed_ms=int((time.perf_counter()-t0)*1000))
            return drf_error("未登录", status=401)
        profile = getattr(user, "profile", None)
        roles = list(profile.roles.values_list("code", flat=True)) if profile else []
        # 若为 Django 超级用户或拥有 admin 角色，追加 ROOT 角色，前端将视为超级管理员
        try:
            is_admin_role = profile.roles.filter(code='admin').exists() if profile else False
        except Exception:
            is_admin_role = False
        if user.is_superuser or is_admin_role:
            if "ROOT" not in roles:
                roles.append("ROOT")

        # 聚合基于角色的菜单权限点（供前端按钮级权限使用）
        perms_set = set()
        try:
            if profile:
                role_ids = list(profile.roles.values_list('id', flat=True))
                if role_ids:
                    from .models import Menu
                    for p in Menu.objects.filter(status=True, roles__in=role_ids).exclude(perms="").values_list("perms", flat=True).distinct():
                        # 支持以逗号/空格分隔的多权限配置
                        for token in str(p).replace('\n', ' ').replace('\t', ' ').split(','):
                            token = token.strip()
                            if token:
                                perms_set.add(token)
        except Exception:
            pass

        perms = sorted(perms_set)
        # 将头像转换为绝对 URL（避免前端在不同端口下 /media 相对路径无法加载）
        def abs_avatar(v: str) -> str:
            try:
                if not v:
                    return ""
                if str(v).startswith("http://") or str(v).startswith("https://"):
                    return v
                # 统一补齐到 MEDIA_URL
                base = settings.MEDIA_URL.rstrip('/')
                p = str(v)
                if p.startswith('/media/'):
                    rel = p
                elif p.startswith('media/'):
                    rel = '/' + p
                elif p.startswith('uploads/'):
                    rel = base + '/' + p
                else:
                    rel = p if p.startswith('/') else ('/' + p)
                # 如果设置了对外可访问的后端 URL（BACKEND_EXTERNAL_URL），优先使用该值构建外部可访问链接
                external = getattr(settings, 'BACKEND_EXTERNAL_URL', '') or ''
                external = external.rstrip('/')
                if external:
                    return external + rel
                # 否则使用 request 的 Host 构建绝对 URI（兼容本地/代理调试）
                return request.build_absolute_uri(rel)
            except Exception:
                return v or ""

        resp = drf_ok({
            "userId": user.id,
            "username": user.username,
            "nickname": profile.nickname if profile else "",
            "avatar": abs_avatar(profile.avatar if profile else ""),
            "roles": roles,
            "perms": perms,
        })
        write_log(request, module='User', action='获取当前登录用户信息', result='success', elapsed_ms=int((time.perf_counter()-t0)*1000))
        return resp

    @action(detail=False, methods=["get"], url_path="page")
    def page(self, request):
        # 支持 pageNum/pageSize/keywords/status/deptId
        qs = User.objects.all().order_by("id")
        kw = request.query_params.get("keywords")
        if kw:
            # 使用 Q 组合 OR，避免 QuerySet union 在分页 count/slice 时报错
            qs = qs.filter(Q(username__icontains=kw) | Q(email__icontains=kw))
        status = request.query_params.get("status")
        if status is not None:
            qs = qs.filter(is_active=bool(int(status)))
        dept_id = request.query_params.get("deptId")
        if dept_id:
            # 包含所选部门及其所有子部门
            try:
                from .models import Department
                target_ids = set()
                def collect(did):
                    if did in target_ids:
                        return
                    target_ids.add(did)
                    for cid in Department.objects.filter(parent_id=did).values_list('id', flat=True):
                        collect(cid)
                collect(int(dept_id))
                qs = qs.filter(profile__dept_id__in=list(target_ids))
            except Exception:
                qs = qs.filter(profile__dept_id=dept_id)
        # 创建时间范围过滤（YYYY-MM-DD ~ YYYY-MM-DD）
        ct_range = request.query_params.get("createTime")
        # 支持前端通过 query string 传递两段 createTime[]=start&createTime[]=end 的情况
        start = request.query_params.getlist('createTime[]') or request.query_params.getlist('createTime')
        if isinstance(ct_range, (list, tuple)):
            start = ct_range
        if start and len(start) >= 2 and start[0] and start[1]:
            from datetime import datetime, timedelta
            try:
                dt_start = datetime.strptime(start[0], "%Y-%m-%d")
                dt_end = datetime.strptime(start[1], "%Y-%m-%d") + timedelta(days=1)
                qs = qs.filter(date_joined__gte=dt_start, date_joined__lt=dt_end)
            except Exception:
                pass

        # 数据权限过滤：基于当前登录用户的所有角色 data_scope 计算可访问用户集合
        # 优先：超级用户 或 拥有 admin 角色 -> 不限制
        user = getattr(request, 'user', None)
        if user and getattr(user, 'is_authenticated', False):
            if not user.is_superuser:
                profile = getattr(user, 'profile', None)
                is_admin_role = False
                try:
                    if profile:
                        is_admin_role = profile.roles.filter(code='admin').exists()
                except Exception:
                    is_admin_role = False
                if not is_admin_role and profile:
                    # 汇总所有角色的 data_scope，采用“并集”策略：若任一角色拥有更广泛范围则扩大可见性
                    scopes = list(profile.roles.values_list('data_scope', flat=True)) or []
                    # 默认无角色则最小范围=本人
                    scopes = scopes or [4]
                    # 若包含 1 (全部数据) 直接跳过限制
                    if 1 not in scopes:
                        # 预取当前用户所属部门及所有子部门
                        dept_ids_union = set()
                        if profile.dept_id:
                            from .models import Department
                            def collect(did):
                                if did in dept_ids_union:
                                    return
                                dept_ids_union.add(did)
                                for cid in Department.objects.filter(parent_id=did).values_list('id', flat=True):
                                    collect(cid)
                            collect(profile.dept_id)
                        # 构造 Q 条件并集
                        perm_q = Q(pk__in=[user.id])  # 本人
                        # 若存在 3 (本部门)，允许同部门用户
                        if 3 in scopes and profile.dept_id:
                            perm_q |= Q(profile__dept_id=profile.dept_id)
                        # 若存在 2 (部门及子部门)，允许当前部门及其子孙
                        if 2 in scopes and dept_ids_union:
                            perm_q |= Q(profile__dept_id__in=list(dept_ids_union))
                        # 将过滤应用（若仅本人则 perm_q 只是本人）
                        qs = qs.filter(perm_q)
        total, items, _, _ = paginate_queryset(request, qs)
        data = UserSerializer(items, many=True).data
        return drf_ok({"total": total, "list": data})

    @action(detail=False, methods=["get"], url_path=r"(?P<user_id>[^/]+)/form")
    def form(self, request, user_id: str):
        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return drf_error("未找到用户", status=404)
        return drf_ok(UserSerializer(user).data)

    @action(detail=False, methods=["post"], url_path="")
    def create(self, request):
        import time
        t0 = time.perf_counter()
        payload = request.data.copy()
        username = payload.get("username")
        password = payload.get("password") or "123456"
        email = payload.get("email") or ""
        nickname = payload.get("nickname") or ""
        mobile = payload.get("mobile") or ""
        # 若未显式传入 avatar，使用 settings.DEFAULT_AVATAR_URL
        from django.conf import settings
        avatar = payload.get("avatar") or getattr(settings, 'DEFAULT_AVATAR_URL', '') or ""
        dept_id = payload.get("deptId")
        role_ids = payload.get("roleIds") or []
        status_num = payload.get("status", 1)
        gender = payload.get("gender")
        if not username:
            write_log(request, module='用户', action='新增用户失败：用户名为空', result='fail', elapsed_ms=int((time.perf_counter()-t0)*1000))
            return drf_error("用户名不能为空", status=400)
        if User.objects.filter(username=username).exists():
            write_log(request, module='用户', action=f'新增用户失败：用户名已存在（{username}）', result='fail', elapsed_ms=int((time.perf_counter()-t0)*1000))
            return drf_error("用户名已存在", status=400)
        user = User.objects.create(username=username, email=email, is_active=bool(int(status_num)))
        user.set_password(password)
        user.save()
        profile = UserProfile.objects.create(user=user, nickname=nickname, mobile=mobile, avatar=avatar, dept_id=dept_id, cloud_id=payload.get("cloudId", "") or "")
        if gender is not None:
            try:
                profile.gender = int(gender)
            except Exception:
                pass
        if role_ids:
            profile.roles.set(Role.objects.filter(id__in=role_ids))
        profile.save()
        write_log(request, module='用户', action=f'新增用户：{username}（ID={user.id}）', result='success', elapsed_ms=int((time.perf_counter()-t0)*1000))
        return drf_ok(UserSerializer(user).data, status=201)

    @action(detail=False, methods=["put"], url_path=r"(?P<id>[^/]+)")
    def update(self, request, id: str):
        import time
        t0 = time.perf_counter()
        try:
            user = User.objects.get(pk=id)
        except User.DoesNotExist:
            write_log(request, module='用户', action=f'更新用户失败：未找到（ID={id}）', result='fail', elapsed_ms=int((time.perf_counter()-t0)*1000))
            return drf_error("未找到用户", status=404)
        payload = request.data.copy()
        user.email = payload.get("email", user.email)
        user.is_active = bool(int(payload.get("status", 1)))
        user.save()
        profile = getattr(user, "profile", None)
        seafile_sync = None
        if profile:
            profile.nickname = payload.get("nickname", profile.nickname)
            profile.mobile = payload.get("mobile", profile.mobile)
            profile.avatar = payload.get("avatar", profile.avatar)
            profile.dept_id = payload.get("deptId", profile.dept_id)
            # 支持通过 API 写入 cloudId（用于手动回填 Seafile 的 cloud identifier）
            if "cloudId" in payload:
                try:
                    profile.cloud_id = payload.get("cloudId") or ""
                except Exception:
                    pass
            if payload.get("gender") is not None:
                try:
                    profile.gender = int(payload.get("gender"))
                except Exception:
                    pass
            role_ids = payload.get("roleIds") or []
            if role_ids:
                profile.roles.set(Role.objects.filter(id__in=role_ids))
            profile.save()
            # 如果配置了 profile.cloud_id，尝试同步更新 Seafile 管理端的信息
            try:
                cloud_id_val = (profile.cloud_id or "").strip()
            except Exception:
                cloud_id_val = ""
            if cloud_id_val:
                seafile_sync = None
                # 读取 Seafile 管理凭据（与 cloud_create/delete 逻辑一致）
                s_site = s_user = s_pass = None
                try:
                    items = list(DictItem.objects.filter(dict_type__code__in=["cloud_type", "clooud_type"], status=True))
                    if items:
                        for it in items:
                            label = (it.label or "").lower()
                            val = (it.value or "").strip()
                            if not s_site and ("site" in label or "站" in label or val.startswith("http")):
                                s_site = val
                                continue
                            if not s_user and ("admin" in label or "管理员" in label or "username" in label):
                                s_user = val
                                continue
                            if not s_pass and ("pass" in label or "密码" in label or "pwd" in label):
                                s_pass = val
                                continue
                        if (not s_site or not s_user or not s_pass) and items[0] and items[0].value:
                            try:
                                j = json.loads(items[0].value)
                                s_site = s_site or j.get("site") or j.get("url") or j.get("host") or j.get("endpoint")
                                s_user = s_user or j.get("username") or j.get("user") or j.get("admin")
                                s_pass = s_pass or j.get("password") or j.get("pass") or j.get("pwd")
                            except Exception:
                                pass
                except Exception:
                    items = []

                if s_site and s_user and s_pass:
                    base_site = str(s_site).strip()
                    if not re.match(r"^https?://", base_site, re.I):
                        base_site = "https://" + base_site
                    auth_url = base_site.rstrip("/")
                    if not re.search(r"api2/auth-token", auth_url, re.I):
                        auth_url = auth_url + "/api2/auth-token/"

                    token = None
                    try:
                        resp = requests.post(auth_url, json={"username": s_user, "password": s_pass}, timeout=10)
                        if 200 <= resp.status_code < 300:
                            try:
                                token = resp.json().get("token")
                            except Exception:
                                token = None
                    except Exception as e:
                        token = None

                    if token:
                        headers = {"Authorization": f"Token {token}", "Accept": "application/json"}
                        admin_put_url = base_site.rstrip("/") + f"/api/v2.1/admin/users/{quote(cloud_id_val)}/"
                        admin_result = {"success": None, "msg": "skipped"}
                        account_result = {"success": None, "msg": "skipped"}
                        try:
                            r = requests.put(admin_put_url, data={"name": profile.nickname or "", "contact_email": user.email or ""}, headers=headers, timeout=10)
                            if 200 <= r.status_code < 300:
                                admin_result = {"success": True, "msg": f"{r.status_code}"}
                            else:
                                admin_result = {"success": False, "msg": f"{r.status_code} {getattr(r, 'text', '')}"}
                        except Exception as e:
                            admin_result = {"success": False, "msg": f"请求失败: {e}"}

                        # 同时向 /api2/accounts/{cloudID}/ 发送 PUT 更新账号状态（is_active）
                        try:
                            account_url = base_site.rstrip("/") + f"/api2/accounts/{quote(cloud_id_val)}/"
                            acct_headers = {"Authorization": f"Token {token}", "Content-Type": "application/x-www-form-urlencoded"}
                            is_active_val = "true" if getattr(user, 'is_active', True) else "false"
                            try:
                                ar = requests.put(account_url, data={"is_active": is_active_val}, headers=acct_headers, timeout=10)
                                if 200 <= ar.status_code < 300:
                                    account_result = {"success": True, "msg": f"{ar.status_code}"}
                                else:
                                    account_result = {"success": False, "msg": f"{ar.status_code} {getattr(ar, 'text', '')}"}
                            except Exception as e:
                                account_result = {"success": False, "msg": f"请求失败: {e}"}
                        except Exception:
                            account_result = {"success": False, "msg": "构建 account_url 失败"}

                        # 构造兼容的 seafile_sync：保留 top-level success，并带上详细项
                        overall = bool(admin_result.get("success") and account_result.get("success"))
                        seafile_sync = {
                            "success": overall,
                            "msg": "",
                            "adminPut": admin_result,
                            "accountPut": account_result,
                        }
                        if not overall:
                            # 用简短信息填充 msg 便于前端展示
                            msgs = []
                            if admin_result.get("success") is False:
                                msgs.append(f"admin:{admin_result.get('msg')}")
                            if account_result.get("success") is False:
                                msgs.append(f"account:{account_result.get('msg')}")
                            seafile_sync["msg"] = "; ".join(msgs) if msgs else seafile_sync.get("msg", "")
                    else:
                        seafile_sync = {"success": False, "msg": "未能获取 Seafile token"}
                else:
                    seafile_sync = {"success": False, "msg": "未配置完整的 Seafile 管理凭据"}
                # 记录同步日志（不影响主流程返回）
                try:
                    write_log(request, module='用户', action=f'同步 Seafile 用户（cloud_id={cloud_id_val}）结果：{seafile_sync}', result='success' if seafile_sync.get('success') else 'partial', elapsed_ms=0)
                except Exception:
                    pass
        write_log(request, module='用户', action=f'更新用户：{user.username}（ID={user.id}）', result='success', elapsed_ms=int((time.perf_counter()-t0)*1000))
        resp_data = UserSerializer(user).data
        # 若有 Seafile 同步结果，将其加入返回数据，便于前端显示
        if seafile_sync is not None:
            resp_data['seafileSync'] = seafile_sync
        return drf_ok(resp_data)

    @action(detail=False, methods=["delete"], url_path=r"(?P<id>[^/]+)")
    def delete(self, request, id: str):
        import time
        t0 = time.perf_counter()
        # 支持单个或逗号分隔的批量删除，并在删除时同步调用 Seafile 的删除接口
        try:
            # 解析 ids 列表
            if isinstance(id, str) and "," in id:
                ids = [s.strip() for s in id.split(",") if s.strip()]
            else:
                ids = [id]

            # 获取待删除用户对象列表
            users_qs = User.objects.filter(id__in=ids)
            if not users_qs.exists():
                write_log(request, module='用户', action=f'删除用户失败：未找到（IDs={id}）', result='fail', elapsed_ms=int((time.perf_counter()-t0)*1000))
                return drf_error("未找到用户", status=404)

            users = list(users_qs)

            cloud_results = []
            # 仅使用 profile.cloud_id 作为远端删除标识；若 profile.cloud_id 未配置，则跳过远端删除并记录
            # 从字典读取 Seafile 配置（复用 cloud_create 的解析逻辑）
            site = admin_user = admin_pass = None
            try:
                items = list(DictItem.objects.filter(dict_type__code__in=["cloud_type", "clooud_type"], status=True))
                if items:
                    for it in items:
                        label = (it.label or "").lower()
                        val = (it.value or "").strip()
                        if not site and ("site" in label or "站" in label or val.startswith("http")):
                            site = val
                            continue
                        if not admin_user and ("admin" in label or "管理员" in label or "username" in label):
                            admin_user = val
                            continue
                        if not admin_pass and ("pass" in label or "密码" in label or "pwd" in label):
                            admin_pass = val
                            continue
                    if (not site or not admin_user or not admin_pass) and items[0] and items[0].value:
                        try:
                            j = json.loads(items[0].value)
                            site = site or j.get("site") or j.get("url") or j.get("host") or j.get("endpoint")
                            admin_user = admin_user or j.get("username") or j.get("user") or j.get("admin")
                            admin_pass = admin_pass or j.get("password") or j.get("pass") or j.get("pwd")
                        except Exception:
                            pass
            except Exception:
                items = []

            # 收集需要在 Seafile 上删除的目标（依据 profile.cloud_id）
            cloud_targets = []
            for u in users:
                profile = getattr(u, 'profile', None)
                try:
                    cloud_id_val = (profile.cloud_id or "").strip() if profile else ""
                except Exception:
                    cloud_id_val = ""
                if cloud_id_val:
                    cloud_targets.append((u, cloud_id_val))
                else:
                    cloud_results.append({"id": u.id, "email": (u.email or ""), "success": False, "msg": "未配置 cloud_id，跳过远端删除"})

            # 若存在需要远程删除的目标且有完整 Seafile 管理凭据，则调用批量删除接口
            if cloud_targets and site and admin_user and admin_pass:
                base_site = str(site).strip()
                if not re.match(r"^https?://", base_site, re.I):
                    base_site = "https://" + base_site
                auth_url = base_site.rstrip("/")
                if not re.search(r"api2/auth-token", auth_url, re.I):
                    auth_url = auth_url + "/api2/auth-token/"

                token = None
                try:
                    resp = requests.post(auth_url, json={"username": admin_user, "password": admin_pass}, timeout=10)
                    if 200 <= resp.status_code < 300:
                        try:
                            token = resp.json().get("token")
                        except Exception:
                            token = None
                except Exception as e:
                    write_log(request, module='用户', action=f'删除用户时获取 Seafile token 失败：{e}', result='fail', elapsed_ms=0)

                if token:
                    headers = {"Authorization": f"Token {token}", "Accept": "application/json"}
                    batch_url = base_site.rstrip("/") + "/api/v2.1/admin/users/batch/"
                    for (u, target_email) in cloud_targets:
                        payload = {"email": target_email, "operation": "delete-user"}
                        try:
                            r = requests.post(batch_url, data=payload, headers=headers, timeout=10)
                            if 200 <= r.status_code < 300:
                                cloud_results.append({"id": u.id, "email": target_email, "success": True, "msg": f"{r.status_code}"})
                            else:
                                txt = getattr(r, 'text', '')
                                cloud_results.append({"id": u.id, "email": target_email, "success": False, "msg": f"{r.status_code} {txt}"})
                        except Exception as e:
                            cloud_results.append({"id": u.id, "email": target_email, "success": False, "msg": f"请求失败: {e}"})
                else:
                    write_log(request, module='用户', action='删除用户时未能获取 Seafile token，跳过远端删除', result='fail', elapsed_ms=0)
            else:
                if cloud_targets and not (site and admin_user and admin_pass):
                    write_log(request, module='用户', action='未在字典中找到完整的 Seafile 管理凭据，跳过远端删除', result='fail', elapsed_ms=0)

            # 执行本地删除
            count = users_qs.count()
            users_qs.delete()
            # 记录日志（包含远端删除汇总信息）
            succ = sum(1 for r in cloud_results if r.get('success'))
            failc = sum(1 for r in cloud_results if not r.get('success'))
            write_log(request, module='用户', action=f'删除用户：{id}（共{count}）。远端删除成功 {succ}，失败 {failc}', result='success' if failc==0 else 'partial', elapsed_ms=int((time.perf_counter()-t0)*1000))
            # 返回本地删除与云端删除的详细结果，前端将据此展示提示
            return drf_ok({
                "deletedCount": count,
                "cloudResults": cloud_results,
                "successCount": succ,
                "failCount": failc,
            })
        except User.DoesNotExist:
            write_log(request, module='用户', action=f'删除用户失败：未找到（ID={id}）', result='fail', elapsed_ms=int((time.perf_counter()-t0)*1000))
            return drf_error("未找到用户", status=404)
        except Exception as e:
            write_log(request, module='用户', action=f'删除用户失败（异常）：{e}', result='fail', elapsed_ms=int((time.perf_counter()-t0)*1000))
            return drf_error("服务器内部错误", status=500)

    @action(detail=False, methods=["put"], url_path=r"(?P<id>[^/]+)/password/reset")
    def reset_password(self, request, id: str):
        import time
        t0 = time.perf_counter()
        try:
            user = User.objects.get(pk=id)
        except User.DoesNotExist:
            write_log(request, module='用户', action=f'重置密码失败：未找到用户（ID={id}）', result='fail', elapsed_ms=int((time.perf_counter()-t0)*1000))
            return drf_error("未找到用户", status=404)
        password = request.query_params.get("password") or "123456"
        user.set_password(password)
        user.save()
        # 尝试同步修改 Seafile 账号密码（若存在 profile.cloud_id）并把结果返回给前端
        seafile_sync = None
        try:
            profile = getattr(user, 'profile', None)
            cloud_id_val = (profile.cloud_id or "").strip() if profile else ""
        except Exception:
            cloud_id_val = ""

        if cloud_id_val:
            # 读取 Seafile 管理凭据
            s_site = s_user = s_pass = None
            try:
                items = list(DictItem.objects.filter(dict_type__code__in=["cloud_type", "clooud_type"], status=True))
                if items:
                    for it in items:
                        label = (it.label or "").lower()
                        val = (it.value or "").strip()
                        if not s_site and ("site" in label or "站" in label or val.startswith("http")):
                            s_site = val
                            continue
                        if not s_user and ("admin" in label or "管理员" in label or "username" in label):
                            s_user = val
                            continue
                        if not s_pass and ("pass" in label or "密码" in label or "pwd" in label):
                            s_pass = val
                            continue
                    if (not s_site or not s_user or not s_pass) and items[0] and items[0].value:
                        try:
                            j = json.loads(items[0].value)
                            s_site = s_site or j.get("site") or j.get("url") or j.get("host") or j.get("endpoint")
                            s_user = s_user or j.get("username") or j.get("user") or j.get("admin")
                            s_pass = s_pass or j.get("password") or j.get("pass") or j.get("pwd")
                        except Exception:
                            pass
            except Exception:
                items = []

            if s_site and s_user and s_pass:
                base_site = str(s_site).strip()
                if not re.match(r"^https?://", base_site, re.I):
                    base_site = "https://" + base_site
                auth_url = base_site.rstrip("/")
                if not re.search(r"api2/auth-token", auth_url, re.I):
                    auth_url = auth_url + "/api2/auth-token/"

                token = None
                try:
                    resp = requests.post(auth_url, json={"username": s_user, "password": s_pass}, timeout=10)
                    if 200 <= resp.status_code < 300:
                        try:
                            token = resp.json().get("token")
                        except Exception:
                            token = None
                except Exception:
                    token = None

                if token:
                    acct_headers = {"Authorization": f"Token {token}", "Content-Type": "application/x-www-form-urlencoded"}
                    account_url = base_site.rstrip("/") + f"/api2/accounts/{quote(cloud_id_val)}/"
                    try:
                        ar = requests.put(account_url, data={"password": password}, headers=acct_headers, timeout=10)
                        if 200 <= ar.status_code < 300:
                            seafile_sync = {"success": True, "msg": f"{ar.status_code}", "accountPut": {"success": True, "msg": f"{ar.status_code}"}}
                        else:
                            seafile_sync = {"success": False, "msg": f"{ar.status_code} {getattr(ar, 'text', '')}", "accountPut": {"success": False, "msg": f"{ar.status_code} {getattr(ar, 'text', '')}"}}
                    except Exception as e:
                        seafile_sync = {"success": False, "msg": f"请求失败: {e}", "accountPut": {"success": False, "msg": f"请求失败: {e}"}}
                else:
                    seafile_sync = {"success": False, "msg": "未能获取 Seafile token", "accountPut": {"success": False, "msg": "未能获取 Seafile token"}}
            else:
                seafile_sync = {"success": False, "msg": "未配置完整的 Seafile 管理凭据", "accountPut": {"success": False, "msg": "未配置完整的 Seafile 管理凭据"}}

        # 记录日志
        write_log(request, module='用户', action=f'重置用户密码（ID={id}）', result='success', elapsed_ms=int((time.perf_counter()-t0)*1000))

        resp = {"message": "password reset"}
        if seafile_sync is not None:
            resp['seafileSync'] = seafile_sync
        return drf_ok(resp)

    @action(detail=False, methods=["get"], url_path="template")
    def template(self, request):
        import time
        t0 = time.perf_counter()
        # 返回一个简单的 CSV 模板
        content = "username,email,nickname,mobile,deptId,roleIds\n"
        response = HttpResponse(content, content_type="text/csv")
        response["Content-Disposition"] = "attachment; filename=users_template.csv"
        write_log(request, module='用户', action='下载用户导入模板', result='success', elapsed_ms=int((time.perf_counter()-t0)*1000))
        return response

    @action(detail=False, methods=["get"], url_path="export")
    def export(self, request):
        import time
        t0 = time.perf_counter()
        # 导出所有用户为 CSV
        users = User.objects.all().order_by("id")
        content = "username,email,nickname,mobile,deptId,roleIds\n"
        for u in users:
            profile = getattr(u, "profile", None)
            role_ids = ",".join(str(r.id) for r in profile.roles.all()) if profile else ""
            dept_id = profile.dept_id if profile else ""
            content += f"{u.username},{u.email},{profile.nickname if profile else ''},{profile.mobile if profile else ''},{dept_id},{role_ids}\n"
        response = HttpResponse(content, content_type="text/csv")
        response["Content-Disposition"] = "attachment; filename=users_export.csv"
        try:
            cnt = users.count()
        except Exception:
            cnt = 0
        write_log(request, module='用户', action=f'导出用户列表：{cnt} 条', result='success', elapsed_ms=int((time.perf_counter()-t0)*1000))
        return response

    @action(detail=False, methods=["post"], url_path="import")
    def import_users(self, request):
        import time
        t0 = time.perf_counter()
        # 支持 CSV 文件导入
        file = request.FILES.get("file")
        if not file:
            write_log(request, module='用户', action='导入用户失败：未上传文件', result='fail', elapsed_ms=int((time.perf_counter()-t0)*1000))
            return drf_error("未上传文件", status=400)
        import csv
        import io
        reader = csv.DictReader(io.StringIO(file.read().decode()))
        count = 0
        from django.conf import settings
        default_avatar = getattr(settings, 'DEFAULT_AVATAR_URL', '')
        for row in reader:
            username = row.get("username")
            if not username or User.objects.filter(username=username).exists():
                continue
            user = User.objects.create(username=username, email=row.get("email", ""), is_active=True)
            user.set_password("123456")
            user.save()
            # 导入时若无头像，使用默认头像
            avatar = row.get("avatar") or default_avatar
            profile = UserProfile.objects.create(user=user, nickname=row.get("nickname", ""), mobile=row.get("mobile", ""), dept_id=row.get("deptId"), avatar=avatar)
            role_ids = row.get("roleIds", "").split(",") if row.get("roleIds") else []
            if role_ids:
                profile.roles.set(Role.objects.filter(id__in=role_ids))
            profile.save()
            count += 1
        write_log(request, module='用户', action=f'导入用户：{count} 条', result='success', elapsed_ms=int((time.perf_counter()-t0)*1000))
        return drf_ok({"success": True, "count": count})

    @action(detail=False, methods=["post"], url_path="cloud-create", permission_classes=[IsAuthenticated])
    def cloud_create(self, request):
        """后端代理：为选中用户在 Seafile 上创建账号。

        请求 JSON:
        { "ids": [1,2,3], "passwords": {"1": "pwd1", "2": "pwd2"} }

        返回:
        { results: [{id, email, username, success, msg}], successCount, failCount }
        """
        data = request.data or {}
        ids = data.get("ids") or data.get("userIds") or []
        if isinstance(ids, str):
            ids = [x.strip() for x in ids.split(",") if x.strip()]
        passwords = data.get("passwords") or {}

        # 读取字典 cloud_type / clooud_type
        site = admin_user = admin_pass = None
        try:
            items = list(DictItem.objects.filter(dict_type__code__in=["cloud_type", "clooud_type"], status=True))
            if items:
                for it in items:
                    label = (it.label or "").lower()
                    val = (it.value or "").strip()
                    if not site and ("site" in label or "站" in label or val.startswith("http")):
                        site = val
                        continue
                    if not admin_user and ("admin" in label or "管理员" in label or "username" in label):
                        admin_user = val
                        continue
                    if not admin_pass and ("pass" in label or "密码" in label or "pwd" in label):
                        admin_pass = val
                        continue
                # 若仍不完整，尝试解析首项为 JSON
                if (not site or not admin_user or not admin_pass) and items[0] and items[0].value:
                    try:
                        j = json.loads(items[0].value)
                        site = site or j.get("site") or j.get("url") or j.get("host") or j.get("endpoint")
                        admin_user = admin_user or j.get("username") or j.get("user") or j.get("admin")
                        admin_pass = admin_pass or j.get("password") or j.get("pass") or j.get("pwd")
                    except Exception:
                        pass
        except Exception:
            items = []

        if not site or not admin_user or not admin_pass:
            return drf_error("未在字典中找到完整的 Seafile 站点和管理员凭据，请在字典 cloud_type 中配置 site/admin/password", status=400)

        base_site = str(site).strip()
        if not re.match(r"^https?://", base_site, re.I):
            base_site = "https://" + base_site
        auth_url = base_site.rstrip("/")
        if not re.search(r"api2/auth-token", auth_url, re.I):
            auth_url = auth_url + "/api2/auth-token/"

        try:
            resp = requests.post(auth_url, json={"username": admin_user, "password": admin_pass}, timeout=10)
        except Exception as e:
            write_log(request, module='用户', action='创建 cloud 用户失败: 获取 token 错误', result='fail', elapsed_ms=0)
            return drf_error(f"请求 Seafile 获取 token 失败: {e}", status=502)

        if resp.status_code < 200 or resp.status_code >= 300:
            try:
                txt = resp.text
            except Exception:
                txt = ""
            write_log(request, module='用户', action=f'创建 cloud 用户失败: Seafile 返回 {resp.status_code}', result='fail', elapsed_ms=0)
            return drf_error(f"Seafile 返回错误: {resp.status_code} {txt}", status=502)

        try:
            token = resp.json().get("token")
        except Exception:
            token = None
        if not token:
            return drf_error("未从 Seafile 获取到 token，请检查字典中管理员账号/密码是否正确", status=502)

        results = []
        success = 0
        fail = 0
        headers = {"Authorization": f"Token {token}", "Content-Type": "application/x-www-form-urlencoded"}
        for uid in ids:
            try:
                u = User.objects.get(pk=uid)
            except Exception:
                results.append({"id": uid, "success": False, "msg": "未找到用户"})
                fail += 1
                continue
            email = (u.email or "").strip()
            if not email:
                results.append({"id": uid, "username": u.username, "success": False, "msg": "未配置邮箱"})
                fail += 1
                continue
            pwd = None
            # 密码可能按 id 字符串或数字 key 存在
            if str(uid) in passwords:
                pwd = passwords.get(str(uid))
            elif isinstance(uid, int) and uid in passwords:
                pwd = passwords.get(uid)  # type: ignore
            if not pwd:
                results.append({"id": uid, "email": email, "username": u.username, "success": False, "msg": "未提供密码"})
                fail += 1
                continue

            account_url = base_site.rstrip("/") + f"/api2/accounts/{quote(email)}/"
            form = {
                "password": pwd,
                "is_staff": "false",
                "is_active": ("true" if getattr(u, 'is_active', True) else "false"),
                "name": (u.profile.nickname if getattr(u, 'profile', None) else u.username),
            }
            try:
                r = requests.put(account_url, data=form, headers=headers, timeout=10)
            except Exception as e:
                results.append({"id": uid, "email": email, "username": u.username, "success": False, "msg": f"请求创建失败: {e}"})
                fail += 1
                continue
            if 200 <= r.status_code < 300:
                # 解析返回 JSON，尝试读取 Seafile 返回的 email 作为 cloud_id 并保存到 profile
                returned_email = None
                try:
                    jr = r.json()
                    returned_email = jr.get("email") if isinstance(jr, dict) else None
                except Exception:
                    returned_email = None
                try:
                    profile = getattr(u, 'profile', None)
                    if profile and returned_email:
                        profile.cloud_id = returned_email
                        profile.save()
                except Exception:
                    pass
                # 若成功创建并获得 returned_email，则向 admin users 接口绑定 login_id
                admin_bind = {"success": None, "msg": "skipped"}
                if returned_email:
                    try:
                        admin_put_url = base_site.rstrip("/") + f"/api/v2.1/admin/users/{quote(returned_email)}/"
                        try:
                            # 以 form-data 方式提交 login_id
                            ap = requests.put(admin_put_url, data={"login_id": u.username}, headers=headers, timeout=10)
                            if 200 <= ap.status_code < 300:
                                admin_bind = {"success": True, "msg": f"{ap.status_code}"}
                            else:
                                admin_bind = {"success": False, "msg": f"{ap.status_code} {getattr(ap, 'text', '')}"}
                        except Exception as e:
                            admin_bind = {"success": False, "msg": f"请求失败: {e}"}
                    except Exception:
                        admin_bind = {"success": False, "msg": "构建 admin_put_url 失败"}

                results.append({"id": uid, "email": email, "username": u.username, "cloudId": returned_email, "success": True, "msg": "created", "adminBind": admin_bind})
                success += 1
            else:
                txt = r.text if hasattr(r, 'text') else ''
                results.append({"id": uid, "email": email, "username": u.username, "success": False, "msg": f"{r.status_code} {txt}"})
                fail += 1

        write_log(request, module='用户', action=f'批量创建 cloud 用户：成功 {success}，失败 {fail}', result='success' if fail==0 else 'partial', elapsed_ms=0)
        return drf_ok({"results": results, "successCount": success, "failCount": fail})

    @action(detail=False, methods=["get"], url_path="profile")
    def profile_get(self, request):
        user = request.user
        if not user.is_authenticated:
            return drf_error("未登录", status=401)
        # 补充前端常用聚合字段（与 /users/me 保持一致但包含更详细的角色/部门信息）
        profile = getattr(user, 'profile', None)
        dept_name = ''
        role_names = ''
        if profile:
            if profile.dept:
                dept_name = profile.dept.name
            try:
                role_names = ','.join(profile.roles.values_list('name', flat=True))
            except Exception:
                role_names = ''
        data = UserSerializer(user).data
        # 补充 seafileCached 布尔，便于前端判断是否需要提示 cloud 密码
        try:
            site = None
            try:
                items = list(DictItem.objects.filter(dict_type__code__in=["cloud_type", "clooud_type"], status=True))
                if items:
                    for it in items:
                        label = (it.label or "").lower()
                        val = (it.value or "").strip()
                        if not site and ("site" in label or "站" in label or val.startswith("http")):
                            site = val
                            break
                    if (not site) and items[0] and items[0].value:
                        try:
                            j = json.loads(items[0].value)
                            site = site or j.get("site") or j.get("url") or j.get("host") or j.get("endpoint")
                        except Exception:
                            pass
            except Exception:
                site = None

            if site:
                base_site = str(site).strip()
                if not re.match(r"^https?://", base_site, re.I):
                    base_site = "https://" + base_site
                try:
                    from .utils.seafile import get_cached_token
                    cached = bool(get_cached_token(user, base_site))
                    data['seafileCached'] = cached
                except Exception:
                    data['seafileCached'] = False
            else:
                data['seafileCached'] = False
        except Exception:
            data['seafileCached'] = False
        # 头像补齐为绝对 URL
        try:
            av = data.get('avatar') or ''
            if av and not str(av).startswith(('http://', 'https://')):
                base = settings.MEDIA_URL.rstrip('/')
                if str(av).startswith('/media/'):
                    rel = av
                elif str(av).startswith('media/'):
                    rel = '/' + str(av)
                elif str(av).startswith('uploads/'):
                    rel = base + '/' + str(av)
                else:
                    rel = av if str(av).startswith('/') else ('/' + str(av))
                data['avatar'] = request.build_absolute_uri(rel)
        except Exception:
            pass
        data['deptName'] = dept_name or data.get('deptName', '')
        data['roleNames'] = role_names or data.get('roleNames', '')
        write_log(request, module='用户', action='查看个人资料', result='success', elapsed_ms=0)
        return drf_ok(data)

    @action(detail=False, methods=["put"], url_path="profile")
    def profile_put(self, request):
        import time
        t0 = time.perf_counter()
        user = request.user
        if not user.is_authenticated:
            return drf_error("未登录", status=401)
        payload = request.data.copy()
        profile = getattr(user, "profile", None)
        seafile_profile_sync = None
        seafile_cached_flag = None
        if profile:
            profile.nickname = payload.get("nickname", profile.nickname)
            profile.mobile = payload.get("mobile", profile.mobile)
            profile.avatar = payload.get("avatar", profile.avatar)
            profile.dept_id = payload.get("deptId", profile.dept_id)
            role_ids = payload.get("roleIds") or []
            if role_ids:
                profile.roles.set(Role.objects.filter(id__in=role_ids))
            profile.save()
            # 尝试使用当前用户凭据同步 Seafile 昵称（必须使用当前账户登录）
            try:
                req_password = (request.data or {}).get('cloudPassword') or (request.data or {}).get('password') or None
            except Exception:
                req_password = None

            try:
                # 读取字典以获取 Seafile 站点地址（site），但不使用字典中的用户名/密码作为登录凭据
                site = None
                items = list(DictItem.objects.filter(dict_type__code__in=["cloud_type", "clooud_type"], status=True))
                if items:
                    for it in items:
                        label = (it.label or "").lower()
                        val = (it.value or "").strip()
                        if not site and ("site" in label or "站" in label or val.startswith("http")):
                            site = val
                            continue
                    if (not site) and items[0] and items[0].value:
                        try:
                            j = json.loads(items[0].value)
                            site = site or j.get("site") or j.get("url") or j.get("host") or j.get("endpoint")
                        except Exception:
                            pass
            except Exception:
                site = None

            if site:
                # 优先尝试使用已缓存的 CloudAuthToken；若不存在或过期，尝试使用前端提供的当前用户密码获取并缓存
                try:
                    base_site = str(site).strip()
                    if not re.match(r"^https?://", base_site, re.I):
                        base_site = "https://" + base_site
                    auth_url = base_site.rstrip("/")
                    if not re.search(r"api2/auth-token", auth_url, re.I):
                        auth_url = auth_url + "/api2/auth-token/"

                    # 优先检查缓存的 token：若存在则直接使用；否则按需要求前端提供当前用户密码以获取并缓存 token
                    try:
                        from .utils.seafile import get_cached_token, get_or_fetch_user_token, sync_profile_name, invalidate_user_token
                        cached = get_cached_token(user, base_site)
                        if cached:
                            try:
                                write_log(request, module='Auth', action=f'use cached seafile token for profile sync (user={user.username})', result='success', elapsed_ms=0)
                            except Exception:
                                pass
                            r = sync_profile_name(base_site, cached, profile.nickname)
                            if r is None:
                                seafile_profile_sync = {"success": False, "msg": "请求失败: Seafile 请求异常"}
                            else:
                                if 200 <= r.status_code < 300:
                                    seafile_profile_sync = {"success": True, "msg": f"{r.status_code}"}
                                else:
                                    if r.status_code in (401, 403):
                                        try:
                                            invalidate_user_token(user, base_site)
                                        except Exception:
                                            pass
                                        seafile_profile_sync = {"success": False, "msg": f"Seafile 认证失败({r.status_code})，已失效缓存，请重新登录以刷新 token"}
                                    else:
                                        seafile_profile_sync = {"success": False, "msg": f"{r.status_code} {getattr(r, 'text', '')}"}
                        else:
                            # cache miss: require frontend to provide current user's password
                            if not req_password:
                                seafile_profile_sync = {"success": False, "msg": "未提供当前用户密码，需提供以完成 Seafile 同步"}
                            else:
                                # 验证当前密码与 Django 存储的密码一致；若不一致则不尝试用管理员凭据回退
                                try:
                                        # 尝试使用前端提供的密码向 Seafile 获取 token（不强制其必须与系统密码一致）
                                        token, err = get_or_fetch_user_token(user, base_site, provided_password=req_password, request=request)
                                        if token:
                                            # 成功从 Seafile 获取 token 后，缓存到后端（便于后续免密访问）
                                            try:
                                                from .utils.seafile import cache_token_for_user
                                                cache_token_for_user(user, base_site, token)
                                                seafile_cached_flag = True
                                            except Exception:
                                                pass

                                            r = sync_profile_name(base_site, token, profile.nickname)
                                            if r is None:
                                                seafile_profile_sync = {"success": False, "msg": "请求失败: Seafile 请求异常"}
                                            else:
                                                if 200 <= r.status_code < 300:
                                                    seafile_profile_sync = {"success": True, "msg": f"{r.status_code}"}
                                                else:
                                                    if r.status_code in (401, 403):
                                                        try:
                                                            invalidate_user_token(user, base_site)
                                                        except Exception:
                                                            pass
                                                        seafile_profile_sync = {"success": False, "msg": f"Seafile 认证失败({r.status_code})，已失效缓存，请重新登录以刷新 token"}
                                                    else:
                                                        seafile_profile_sync = {"success": False, "msg": f"{r.status_code} {getattr(r, 'text', '')}"}
                                        else:
                                            seafile_profile_sync = err or {"success": False, "msg": "未能获取 Seafile token"}
                                except Exception:
                                    seafile_profile_sync = {"success": False, "msg": "Seafile 同步异常"}
                    except Exception:
                        seafile_profile_sync = {"success": False, "msg": "Seafile 同步异常"}
                except Exception:
                    seafile_profile_sync = {"success": False, "msg": "Seafile 同步异常"}
            else:
                if not site:
                    seafile_profile_sync = {"success": False, "msg": "未配置 Seafile 站点，请在字典 cloud_type 中配置 site"}
                elif not req_password:
                    seafile_profile_sync = {"success": False, "msg": "未提供当前用户密码，跳过 Seafile 同步"}
        user.email = payload.get("email", user.email)
        user.save()
        write_log(request, module='用户', action='修改个人资料', result='success', elapsed_ms=int((time.perf_counter()-t0)*1000))
        resp_data = UserSerializer(user).data
        if seafile_profile_sync is not None:
            resp_data['seafileProfileSync'] = seafile_profile_sync
        if seafile_cached_flag:
            # 告知前端已缓存 token（布尔）
            resp_data['seafileCached'] = True
        return drf_ok(resp_data)

    @action(detail=False, methods=["put"], url_path="password")
    def change_password(self, request):
        import time
        t0 = time.perf_counter()
        user = request.user
        if not user.is_authenticated:
            return drf_error("未登录", status=401)
        payload = request.data.copy()
        old_pwd = payload.get("oldPassword")
        new_pwd = payload.get("newPassword")
        if not user.check_password(old_pwd):
            write_log(request, module='用户', action='修改密码失败：原密码错误', result='fail', elapsed_ms=int((time.perf_counter()-t0)*1000))
            return drf_error("原密码错误", status=400)
        user.set_password(new_pwd)
        user.save()
        # 尝试使用字典中的 Seafile 管理员凭据同步云端账号密码（仅当 profile.cloud_id 存在时）
        seafile_sync = None
        try:
            profile = getattr(user, 'profile', None)
            cloud_id_val = (profile.cloud_id or "").strip() if profile else ""
        except Exception:
            cloud_id_val = ""

        if cloud_id_val:
            # 读取 Seafile 管理凭据（与 reset_password 逻辑一致）
            s_site = s_user = s_pass = None
            try:
                items = list(DictItem.objects.filter(dict_type__code__in=["cloud_type", "clooud_type"], status=True))
                if items:
                    for it in items:
                        label = (it.label or "").lower()
                        val = (it.value or "").strip()
                        if not s_site and ("site" in label or "站" in label or val.startswith("http")):
                            s_site = val
                            continue
                        if not s_user and ("admin" in label or "管理员" in label or "username" in label):
                            s_user = val
                            continue
                        if not s_pass and ("pass" in label or "密码" in label or "pwd" in label):
                            s_pass = val
                            continue
                    if (not s_site or not s_user or not s_pass) and items[0] and items[0].value:
                        try:
                            j = json.loads(items[0].value)
                            s_site = s_site or j.get("site") or j.get("url") or j.get("host") or j.get("endpoint")
                            s_user = s_user or j.get("username") or j.get("user") or j.get("admin")
                            s_pass = s_pass or j.get("password") or j.get("pass") or j.get("pwd")
                        except Exception:
                            pass
            except Exception:
                items = []

            if s_site and s_user and s_pass:
                base_site = str(s_site).strip()
                if not re.match(r"^https?://", base_site, re.I):
                    base_site = "https://" + base_site
                auth_url = base_site.rstrip("/")
                if not re.search(r"api2/auth-token", auth_url, re.I):
                    auth_url = auth_url + "/api2/auth-token/"

                token = None
                try:
                    resp = requests.post(auth_url, json={"username": s_user, "password": s_pass}, timeout=10)
                    if 200 <= resp.status_code < 300:
                        try:
                            token = resp.json().get("token")
                        except Exception:
                            token = None
                except Exception:
                    token = None

                if token:
                    acct_headers = {"Authorization": f"Token {token}", "Content-Type": "application/x-www-form-urlencoded"}
                    try:
                        account_url = base_site.rstrip("/") + f"/api2/accounts/{quote(cloud_id_val)}/"
                        ar = requests.put(account_url, data={"password": new_pwd}, headers=acct_headers, timeout=10)
                        if 200 <= ar.status_code < 300:
                            seafile_sync = {"success": True, "msg": f"{ar.status_code}", "accountPut": {"success": True, "msg": f"{ar.status_code}"}}
                        else:
                            seafile_sync = {"success": False, "msg": f"{ar.status_code} {getattr(ar, 'text', '')}", "accountPut": {"success": False, "msg": f"{ar.status_code} {getattr(ar, 'text', '')}"}}
                    except Exception as e:
                        seafile_sync = {"success": False, "msg": f"请求失败: {e}", "accountPut": {"success": False, "msg": f"请求失败: {e}"}}
                else:
                    seafile_sync = {"success": False, "msg": "未能获取 Seafile token", "accountPut": {"success": False, "msg": "未能获取 Seafile token"}}
            else:
                seafile_sync = {"success": False, "msg": "未配置完整的 Seafile 管理凭据", "accountPut": {"success": False, "msg": "未配置完整的 Seafile 管理凭据"}}

        # 记录操作日志
        write_log(request, module='用户', action='修改密码成功', result='success', elapsed_ms=int((time.perf_counter()-t0)*1000))
        resp = {"message": "password changed"}
        if seafile_sync is not None:
            resp['seafileSync'] = seafile_sync
            try:
                write_log(request, module='用户', action=f'同步 Seafile 密码 结果：{seafile_sync}', result='success' if seafile_sync.get('success') else 'partial', elapsed_ms=0)
            except Exception:
                pass
        return drf_ok(resp)

    @action(detail=False, methods=["post"], url_path="avatar")
    def upload_avatar(self, request):
        """上传头像，仅用于用户头像，不恢复通用文件上传模块。

        请求：multipart/form-data，字段名 file
        响应：{ url, name, seafileAvatarSync? }
        """
        user = request.user
        if not getattr(user, 'is_authenticated', False):
            return drf_error("未登录", status=401)
        file = request.FILES.get('file')
        if not file:
            return drf_error("未选择文件", status=400)
        # 基本校验：仅允许图片，限制大小 2MB
        content_type = getattr(file, 'content_type', '') or ''
        if not content_type.startswith('image/'):
            return drf_error("仅支持图片文件", status=400)
        max_mb = 2
        if getattr(file, 'size', 0) > max_mb * 1024 * 1024:
            return drf_error(f"图片过大，不能超过 {max_mb}MB", status=400)

        # 保存到本地存储
        from datetime import datetime
        now = datetime.utcnow()
        ext = os.path.splitext(file.name)[1] or ''
        if not ext:
            ext = {
                'image/png': '.png',
                'image/jpeg': '.jpg',
                'image/gif': '.gif',
                'image/webp': '.webp',
            }.get(content_type, '')
        rel_path = f"uploads/avatars/{now.year:04d}/{now.month:02d}/{uuid.uuid4().hex}{ext}"
        saved_path = default_storage.save(rel_path, file)
        media_rel = settings.MEDIA_URL.rstrip('/') + '/' + saved_path.lstrip('/')
        url = request.build_absolute_uri(media_rel)
        write_log(request, module='用户', action='上传头像', result='success', elapsed_ms=0)

        seafile_avatar_sync = None
        seafile_cached_flag = None

        # 尝试读取 site（仅 site），不使用字典中的 admin 凭据进行回退
        site = None
        try:
            items = list(DictItem.objects.filter(dict_type__code__in=["cloud_type", "clooud_type"], status=True))
            if items:
                for it in items:
                    label = (it.label or "").lower()
                    val = (it.value or "").strip()
                    if not site and ("site" in label or "站" in label or val.startswith("http")):
                        site = val
                        break
                if (not site) and items[0] and items[0].value:
                    try:
                        j = json.loads(items[0].value)
                        site = site or j.get("site") or j.get("url") or j.get("host") or j.get("endpoint")
                    except Exception:
                        pass
        except Exception:
            site = None

        # 前端可选提供 cloudPassword
        req_password = (request.data or {}).get('cloudPassword') or (request.data or {}).get('password') or None

        if site:
            base_site = str(site).strip()
            if not re.match(r"^https?://", base_site, re.I):
                base_site = "https://" + base_site

            try:
                from .utils.seafile import get_cached_token, get_or_fetch_user_token, sync_avatar, invalidate_user_token
            except Exception:
                get_cached_token = None
                get_or_fetch_user_token = None
                sync_avatar = None
                invalidate_user_token = None

            cached = None
            if get_cached_token:
                try:
                    cached = get_cached_token(user, base_site)
                except Exception:
                    cached = None

            if cached and sync_avatar:
                try:
                    fobj = default_storage.open(saved_path, 'rb')
                    r = sync_avatar(base_site, cached, fobj, os.path.basename(saved_path), content_type)
                    try:
                        fobj.close()
                    except Exception:
                        pass
                    if r is None:
                        seafile_avatar_sync = {"success": False, "msg": "请求失败: Seafile 请求异常"}
                    else:
                        if 200 <= r.status_code < 300:
                            seafile_avatar_sync = {"success": True, "msg": f"{r.status_code}"}
                        else:
                            if r.status_code in (401, 403):
                                try:
                                    if invalidate_user_token:
                                        invalidate_user_token(user, base_site)
                                except Exception:
                                    pass
                                seafile_avatar_sync = {"success": False, "msg": f"Seafile 认证失败({r.status_code})，已失效缓存，请重新输入密码以刷新 token"}
                            else:
                                seafile_avatar_sync = {"success": False, "msg": f"{r.status_code} {getattr(r, 'text', '')}"}
                except Exception as e:
                    seafile_avatar_sync = {"success": False, "msg": f"请求失败: {e}"}
            else:
                # cache miss -> require password. Do NOT require local check_password before attempting
                # to fetch token from Seafile; only cache token when provided password equals system password.
                if not req_password:
                    seafile_avatar_sync = {"success": False, "msg": "未提供当前用户密码，需提供以完成 Seafile 同步"}
                else:
                    if get_or_fetch_user_token:
                        token, err = get_or_fetch_user_token(user, base_site, provided_password=req_password, request=request)
                    else:
                        token, err = (None, {"success": False, "msg": "Seafile helper 未就绪"})
                    if token and sync_avatar:
                        # 成功从 Seafile 获取 token 后，缓存到后端（便于下次免密）
                        try:
                            from .utils.seafile import cache_token_for_user
                            cache_token_for_user(user, base_site, token)
                            seafile_cached_flag = True
                        except Exception:
                            pass

                        try:
                            fobj = default_storage.open(saved_path, 'rb')
                            r = sync_avatar(base_site, token, fobj, os.path.basename(saved_path), content_type)
                            try:
                                fobj.close()
                            except Exception:
                                pass
                            if r is None:
                                seafile_avatar_sync = {"success": False, "msg": "请求失败: Seafile 请求异常"}
                            else:
                                if 200 <= r.status_code < 300:
                                    seafile_avatar_sync = {"success": True, "msg": f"{r.status_code}"}
                                else:
                                    if r.status_code in (401, 403):
                                        try:
                                            if invalidate_user_token:
                                                invalidate_user_token(user, base_site)
                                        except Exception:
                                            pass
                                        seafile_avatar_sync = {"success": False, "msg": f"Seafile 认证失败({r.status_code})，已失效缓存，请重新输入密码以刷新 token"}
                                    else:
                                        seafile_avatar_sync = {"success": False, "msg": f"{r.status_code} {getattr(r, 'text', '')}"}
                        except Exception as e:
                            seafile_avatar_sync = {"success": False, "msg": f"请求失败: {e}"}
                    else:
                        seafile_avatar_sync = err or {"success": False, "msg": "未能获取 Seafile token"}
        else:
            seafile_avatar_sync = {"success": False, "msg": "未配置 Seafile 站点，请在字典 cloud_type 中配置 site"}

        # 建议裁剪信息 & 预置缩略图（头像常用 256/128/64）
        suggest = {"aspect": "1:1", "recommended": [256, 128, 64]}
        resp = {"url": url, "name": os.path.basename(saved_path), "suggestCrop": suggest}
        if seafile_avatar_sync is not None:
            resp['seafileAvatarSync'] = seafile_avatar_sync
            if seafile_cached_flag:
                resp['seafileCached'] = True
            # 写日志记录
            try:
                write_log(request, module='用户', action=f'同步 Seafile 头像 结果：{seafile_avatar_sync}', result='success' if seafile_avatar_sync.get('success') else 'partial', elapsed_ms=0)
            except Exception:
                pass
        return drf_ok(resp)

    # 通用精简图片上传（非头像），供富文本/普通图片组件复用
    @action(detail=False, methods=["post"], url_path="upload-image")
    def upload_image(self, request):
        """精简图片上传接口，不恢复旧文件系统。\n\n        请求: multipart/form-data, 字段 file\n        可选参数: thumbs=64,128,256 (逗号分隔)，若不传使用默认 64,128,256\n        响应: { url, name, width, height, size, thumbs: {"64": url, ...} }\n        限制: 图片 <=2MB, 仅 image/* MIME\n        """
        user = request.user
        # 可选：允许未登录富文本临时上传？此处若要求登录就返回 401
        if not getattr(user, 'is_authenticated', False):
            return drf_error("未登录", status=401)
        file = request.FILES.get('file')
        if not file:
            return drf_error("未选择文件", status=400)
        ctype = getattr(file, 'content_type', '') or ''
        if not ctype.startswith('image/'):
            return drf_error("仅支持图片", status=400)
        if getattr(file, 'size', 0) > 2 * 1024 * 1024:
            return drf_error("图片过大(>2MB)", status=400)
        # 保存原图
        from datetime import datetime
        now = datetime.utcnow()
        ext = os.path.splitext(file.name)[1] or ''
        rel_path = f"uploads/images/{now.year:04d}/{now.month:02d}/{uuid.uuid4().hex}{ext}"
        saved_path = default_storage.save(rel_path, file)
        media_rel = settings.MEDIA_URL.rstrip('/') + '/' + saved_path.lstrip('/')
        base_url = request.build_absolute_uri(media_rel)
        # 读取尺寸
        try:
            file.seek(0)
            img = Image.open(file)
            width, height = img.size
        except Exception:
            width = height = None
        # 生成缩略图
        thumbs_param = request.query_params.get('thumbs') or request.data.get('thumbs')
        sizes = []
        if thumbs_param:
            for tok in str(thumbs_param).split(','):
                tok = tok.strip()
                if tok.isdigit():
                    sizes.append(int(tok))
        if not sizes:
            sizes = [64, 128, 256]
        thumbs = {}
        try:
            if width and height:
                img.load()
                for s in sizes:
                    try:
                        thumb = img.copy()
                        thumb.thumbnail((s, s))
                        t_rel = f"uploads/images/{now.year:04d}/{now.month:02d}/{uuid.uuid4().hex}_{s}{ext or '.jpg'}"
                        from io import BytesIO
                        buf = BytesIO()
                        save_fmt = 'JPEG'
                        if ext.lower() in ('.png', '.gif', '.webp'):
                            save_fmt = ext.replace('.', '').upper()
                        thumb.save(buf, format=save_fmt if save_fmt != 'JPG' else 'JPEG')
                        buf.seek(0)
                        default_storage.save(t_rel, buf)
                        t_rel_url = settings.MEDIA_URL.rstrip('/') + '/' + t_rel.lstrip('/')
                        thumbs[str(s)] = request.build_absolute_uri(t_rel_url)
                    except Exception:
                        continue
        except Exception:
            pass
        write_log(request, module='用户', action='上传图片(通用)', result='success', elapsed_ms=0)
        return drf_ok({
            "url": base_url,
            "name": os.path.basename(saved_path),
            "width": width,
            "height": height,
            "size": getattr(file, 'size', None),
            "thumbs": thumbs,
            "suggestCrop": {"aspect": "1:1", "recommended": [256, 128, 64]},
        })

    @action(detail=False, methods=["get"], url_path="options")
    def options(self, request):
        users = User.objects.filter(is_active=True).order_by("id")
        data = [{"label": u.username, "value": u.id} for u in users]
        return drf_ok(data)

    @staticmethod
    def generic_get(request):
        # 兼容 GET /users -> 返回全部列表（前端主要使用 /users/page）
        users = User.objects.all().order_by("id")
        return drf_ok([UserSerializer(u).data for u in users])


class ProfileViewSet(viewsets.ViewSet):
    """手机号/邮箱的验证码发送与绑定

    路由：
    - POST /users/mobile/code   发送手机验证码
    - PUT  /users/mobile        绑定手机号
    - POST /users/email/code    发送邮箱验证码
    - PUT  /users/email         绑定邮箱
    所有入参均做基本格式校验。
    """
    # 绑定手机号/邮箱应要求登录，使用全局默认权限（IsAuthenticated）

    @action(detail=False, methods=["post"], url_path="mobile/code")
    def send_mobile_code(self, request):
        s = MobileCodeSendSerializer(data=request.query_params or request.data)
        s.is_valid(raise_exception=True)
        write_log(request, module='用户', action='发送手机验证码', result='success', elapsed_ms=0)
        return drf_ok({"message": "sent"})

    @action(detail=False, methods=["put"], url_path="mobile")
    def bind_mobile(self, request):
        s = MobileBindSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        write_log(request, module='用户', action='绑定手机号', result='success', elapsed_ms=0)
        return drf_ok({"message": "mobile bound"})

    @action(detail=False, methods=["post"], url_path="email/code")
    def send_email_code(self, request):
        s = EmailCodeSendSerializer(data=request.query_params or request.data)
        s.is_valid(raise_exception=True)
        write_log(request, module='用户', action='发送邮箱验证码', result='success', elapsed_ms=0)
        return drf_ok({"message": "sent"})

    @action(detail=False, methods=["put"], url_path="email")
    def bind_email(self, request):
        s = EmailBindSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        write_log(request, module='用户', action='绑定邮箱', result='success', elapsed_ms=0)
        return drf_ok({"message": "email bound"})


# --- Roles ---
class RoleViewSet(viewsets.ViewSet):
    """角色管理（已接入 ORM）

    - GET  /roles/page                 分页查询，支持 pageNum/pageSize/keyword
    - GET  /roles/options              启用角色下拉
    - GET  /roles                      列表
    - POST /roles                      新建
    - GET  /roles/{id}/form            表单详情
    - PUT  /roles/{ids}                更新（ids 逗号分隔，仅取首个）
    - DELETE /roles/{ids}              批量删除
    统一返回：分页 {total,list}；非分页直接返回数据。
    """

    # 针对不同动作声明所需的权限标识
    # query -> sys:role:query, create -> sys:role:add, update -> sys:role:edit, delete -> sys:role:delete
    permission_classes = [MenuPermRequired]

    def get_permissions(self):
        # 根据当前 action/方法设置 required_perms，供 MenuPermRequired 判断
        action = getattr(self, 'action', None)
        method = getattr(self.request, 'method', '').upper() if hasattr(self, 'request') else ''
        required = None
        if action in ("page", "options", "form", "menu_ids") or (action == "list_or_create" and method == 'GET'):
            required = ["sys:role:query"]
        elif (action == "list_or_create" and method == 'POST'):
            required = ["sys:role:add"]
        elif (action == "update_or_delete" and method == 'PUT') or action == "update_menus":
            required = ["sys:role:edit"]
        elif (action == "update_or_delete" and method == 'DELETE'):
            required = ["sys:role:delete"]
        # 将 required_perms 赋给实例，供权限类读取
        if required is not None:
            setattr(self, 'required_perms', required)
        else:
            # 默认仅要求登录（若全局权限为 IsAuthenticated），此处不给 required_perms 则放行
            setattr(self, 'required_perms', None)
        return super().get_permissions()

    @action(detail=False, methods=["get"], url_path="page")
    def page(self, request):
        qs = Role.objects.all().order_by("order_num", "id")
        # 兼容 keyword/keywords 两种参数名
        keyword = request.query_params.get("keyword") or request.query_params.get("keywords")
        if isinstance(keyword, str):
            kw = keyword.strip()
            if kw:
                qs = qs.filter(Q(name__icontains=kw) | Q(code__icontains=kw))
        total, items, _, _ = paginate_queryset(request, qs)
        data = RoleSerializer(items, many=True).data
        return drf_ok({"total": total, "list": data})

    @action(detail=False, methods=["get"], url_path="options")
    def options(self, request):
        data = [
            {"label": r.name, "value": r.id}
            for r in Role.objects.filter(status=True).order_by("order_num", "id")
        ]
        return drf_ok(data)

    @action(detail=False, methods=["get", "post"], url_path="")
    def list_or_create(self, request):
        if request.method.lower() == 'get':
            items = Role.objects.all().order_by("order_num", "id")
            data = RoleSerializer(items, many=True).data
            return drf_ok(data)
        # POST create
        import time
        t0 = time.perf_counter()
        s = RoleWriteSerializer(data=request.data)
        if s.is_valid():
            role = s.save()
            write_log(request, module='角色', action=f'新增角色：{role.name}（ID={role.id}）', result='success', elapsed_ms=int((time.perf_counter()-t0)*1000))
            return drf_ok(RoleSerializer(role).data, status=201)
        write_log(request, module='角色', action='新增角色失败：参数错误', result='fail', elapsed_ms=int((time.perf_counter()-t0)*1000))
        return drf_error("参数错误", data=s.errors, status=400)

    @action(detail=False, methods=["get"], url_path=r"(?P<id>[^/]+)/form")
    def form(self, request, id: str):
        try:
            role = Role.objects.get(pk=id)
        except Role.DoesNotExist:
            return drf_error("未找到角色", status=404)
        return drf_ok(RoleSerializer(role).data)

    @action(detail=False, methods=["put", "delete"], url_path=r"(?P<ids>[^/]+)")
    def update_or_delete(self, request, ids: str):
        if request.method.lower() == 'put':
            first_id = ids.split(',')[0]
            try:
                role = Role.objects.get(pk=first_id)
            except Role.DoesNotExist:
                return drf_error("未找到角色", status=404)
            s = RoleWriteSerializer(role, data=request.data, partial=True)
            if s.is_valid():
                role = s.save()
                write_log(request, module='角色', action=f'更新角色：{role.name}（ID={role.id}）', result='success', elapsed_ms=0)
                return drf_ok(RoleSerializer(role).data)
            write_log(request, module='角色', action='更新角色失败：参数错误', result='fail', elapsed_ms=0)
            return drf_error("参数错误", data=s.errors, status=400)
        id_list = [i for i in ids.split(',') if i]
        Role.objects.filter(id__in=id_list).delete()
        write_log(request, module='角色', action=f'删除角色：{ids}', result='success', elapsed_ms=0)
        return drf_ok(status=204)

    @action(detail=True, methods=["get"], url_path="menuIds")
    def menu_ids(self, request, role_id: str = None, pk: str = None):
        # DRF detail=True 会将参数命名为 pk，这里兼容 urlconf 传入的 role_id
        rid = role_id or pk
        try:
            role = Role.objects.get(pk=rid)
        except Role.DoesNotExist:
            return drf_error("未找到角色", status=404)
        ids = list(role.menus.values_list('id', flat=True))
        return drf_ok(ids)

    @action(detail=True, methods=["put"], url_path="menus")
    def update_menus(self, request, role_id: str = None, pk: str = None):
        rid = role_id or pk
        try:
            role = Role.objects.get(pk=rid)
        except Role.DoesNotExist:
            return drf_error("未找到角色", status=404)
        ids = request.data if isinstance(request.data, list) else request.data.get("menuIds")
        if ids is None:
            return drf_error("缺少 menuIds", status=400)
        role.menus.set(Menu.objects.filter(id__in=ids))
        try:
            cnt = len(ids) if isinstance(ids, list) else (len(ids) if ids else 0)
        except Exception:
            cnt = 0
        write_log(request, module='角色', action=f'分配角色菜单：{role.name}（ID={role.id}），{cnt} 个菜单', result='success', elapsed_ms=0)
        return drf_ok({"success": True})


# --- Notices ---
class NoticeViewSet(viewsets.ViewSet):
    """通知公告接口

    权限映射（按钮级）：
    - 查询: sys:notice:query -> page / form / detail / list_or_create(GET) / my_page
    - 新增: sys:notice:add -> list_or_create(POST)
    - 编辑: sys:notice:edit -> update_or_delete(PUT)
    - 删除: sys:notice:delete -> update_or_delete(DELETE)
    - 发布: sys:notice:publish -> publish
    - 撤回: sys:notice:revoke -> revoke

    说明：read-all 与 my-page 仅查询，归入查询权限；普通用户若无任何按钮权限但被分配了“通知公告”菜单将无法访问数据（需至少具备 sys:notice:query）。
    """
    permission_classes = [MenuPermRequired]

    def get_permissions(self):  # 与其它 ViewSet 保持一致：根据 action+method 设置 required_perms
        action = getattr(self, 'action', None)
        method = getattr(self.request, 'method', '').upper() if hasattr(self, 'request') else ''
        required = None
        # 允许已登录用户查看公告列表和我的公告（只读），管理操作仍需按钮级权限
        if action in ("form", "detail",) or (action == "list_or_create" and method == 'GET'):
            # 表单/详情/管理列表仍要求查询权限（管理页面中的详情与表单）
            required = ["sys:notice:query"]
        elif action in ("page", "my_page"):
            # 公告列表和我的公告对已登录用户开放（不强制按钮级权限）
            required = None
        elif action == "list_or_create" and method == 'POST':
            required = ["sys:notice:add"]
        elif action == "update_or_delete" and method == 'PUT':
            required = ["sys:notice:edit"]
        elif action == "update_or_delete" and method == 'DELETE':
            required = ["sys:notice:delete"]
        elif action == "publish":
            required = ["sys:notice:publish"]
        elif action == "revoke":
            required = ["sys:notice:revoke"]
        # read-all 暂归入查询权限，若无查询权限则不可标记全部已读
        elif action == "read_all":
            required = ["sys:notice:query"]
        setattr(self, 'required_perms', required)
        return super().get_permissions()

    @staticmethod
    def _serialize_brief(n: Notice):
        return NoticeBriefSerializer(n).data

    def _serialize_detail(self, n: Notice):
        data = self._serialize_brief(n)
        data.update({
            "content": n.content,
        })
        return data

    @action(detail=False, methods=["get"], url_path="page")
    def page(self, request):
        qs = Notice.objects.all().order_by("-id")
        kw = request.query_params.get("title") or request.query_params.get("keywords")
        if kw:
            qs = qs.filter(title__icontains=kw)
        publish_status = request.query_params.get("publishStatus")
        if publish_status is not None:
            # 0: draft, 1: published, 2/-1: revoked（兼容前端使用 -1 表示撤回）
            mapping = {"0": 'draft', "1": 'published', "2": 'revoked', "-1": 'revoked'}
            status_val = mapping.get(str(publish_status))
            if status_val:
                qs = qs.filter(status=status_val)
        total, items, _, _ = paginate_queryset(request, qs)
        # 支持过滤已读状态：isRead=0 表示仅未读（针对当前用户）
        is_read = request.query_params.get('isRead')
        if is_read is not None and str(is_read) == '0':
            user = getattr(request, 'user', None)
            if user and getattr(user, 'is_authenticated', False):
                try:
                    from .models import NoticeRead
                    read_ids = list(NoticeRead.objects.filter(user=user).values_list('notice_id', flat=True))
                    items = [i for i in items if i.id not in read_ids]
                except Exception:
                    pass

        data = NoticeBriefSerializer(items, many=True).data
        return drf_ok({"total": total, "list": data})

    @action(detail=False, methods=["get"], url_path=r"(?P<id>[^/]+)/form")
    def form(self, request, id: str):
        try:
            n = Notice.objects.get(pk=id)
        except Notice.DoesNotExist:
            return drf_error("未找到公告", status=404)
        return drf_ok(NoticeDetailSerializer(n).data)

    @action(detail=False, methods=["post"], url_path=r"(?P<id>[^/]+)/publish")
    def publish(self, request, id: str):
        import time
        t0 = time.perf_counter()
        try:
            n = Notice.objects.get(pk=id)
        except Notice.DoesNotExist:
            write_log(request, module='公告', action=f'发布公告失败：未找到（ID={id}）', result='fail', elapsed_ms=int((time.perf_counter()-t0)*1000))
            return drf_error("未找到公告", status=404)
        n.status = 'published'
        n.publish_time = timezone.now()
        n.revoke_time = None
        n.save()
        write_log(request, module='公告', action=f'发布公告：{n.title}（ID={id}）', result='success', elapsed_ms=int((time.perf_counter()-t0)*1000))
        return drf_ok({"message": "published"})

    @action(detail=False, methods=["post"], url_path=r"(?P<id>[^/]+)/revoke")
    def revoke(self, request, id: str):
        import time
        t0 = time.perf_counter()
        try:
            n = Notice.objects.get(pk=id)
        except Notice.DoesNotExist:
            write_log(request, module='公告', action=f'撤回公告失败：未找到（ID={id}）', result='fail', elapsed_ms=int((time.perf_counter()-t0)*1000))
            return drf_error("未找到公告", status=404)
        n.status = 'revoked'
        n.revoke_time = timezone.now()
        n.save()
        write_log(request, module='公告', action=f'撤回公告：{n.title}（ID={id}）', result='success', elapsed_ms=int((time.perf_counter()-t0)*1000))
        return drf_ok({"message": "revoked"})

    # 取消 @action 装饰，避免与手工 urls 映射交叉导致异常；使用普通方法名 detail_plain
    def detail_plain(self, request, id: str):
        n = Notice.objects.get(pk=id)
        data = NoticeDetailSerializer(n).data
        return drf_ok(data)

    @action(detail=False, methods=["post"], url_path="read-all")
    def read_all(self, request):
        # 标记当前用户的所有已发布公告为已读
        user = getattr(request, 'user', None)
        if not user or not getattr(user, 'is_authenticated', False):
            return drf_error("未登录", status=401)
        try:
            from .models import NoticeRead
            # 获取所有已发布公告 id
            ids = list(Notice.objects.filter(status='published').values_list('id', flat=True))
            created = 0
            for nid in ids:
                obj, created_flag = NoticeRead.objects.get_or_create(user=user, notice_id=nid)
                if created_flag:
                    created += 1
            write_log(request, module='公告', action='公告全部标记为已读', result='success', elapsed_ms=0)
            return drf_ok({"message": "read all", "created": created})
        except Exception:
            write_log(request, module='公告', action='公告全部标记为已读失败', result='fail', elapsed_ms=0)
            return drf_error("标记已读失败")

    @action(detail=False, methods=["get"], url_path="my-page")
    def my_page(self, request):
        # 简化：我的公告=已发布公告的分页
        request.GET._mutable = True  # type: ignore
        request.GET["publishStatus"] = "1"
        # 排除当前用户已读的公告
        user = getattr(request, 'user', None)
        if user and getattr(user, 'is_authenticated', False):
            try:
                from .models import NoticeRead
                read_ids = list(NoticeRead.objects.filter(user=user).values_list('notice_id', flat=True))
                # 将一个参数传递给 page 过滤使用，page 方法会读取 request.query_params
                # 这里我们直接调用 page 并在返回结果前过滤
                resp = self.page(request)
                if resp and isinstance(resp, dict) is False:
                    # drf_ok 返回的是 Response，对其 data 做过滤
                    try:
                        data = resp.data
                        if data and isinstance(data, dict) and 'list' in data:
                            data['list'] = [item for item in data['list'] if item.get('id') not in read_ids]
                            resp.data = data
                    except Exception:
                        pass
                return resp
            except Exception:
                return self.page(request)
        return self.page(request)

    @action(detail=False, methods=["get", "post"], url_path="")
    def list_or_create(self, request):
        if request.method.lower() == 'get':
            items = Notice.objects.all().order_by("-id")
            return drf_ok([self._serialize_brief(n) for n in items])
        import time
        t0 = time.perf_counter()
        p = request.data.copy()
        n = Notice.objects.create(
            title=p.get("title") or "",
            content=p.get("content") or "",
            type=p.get("type") or "general",
            status='draft',
            creator=request.user if getattr(request, 'user', None) and request.user.is_authenticated else None,
        )
        write_log(request, module='公告', action=f'新增公告：{n.title}（ID={n.id}）', result='success', elapsed_ms=int((time.perf_counter()-t0)*1000))
        return drf_ok(self._serialize_detail(n), status=201)

    @action(detail=True, methods=["post"], url_path="read")
    def read(self, request, id: str):
        # 标记单条公告为已读（对当前用户）
        user = getattr(request, 'user', None)
        if not user or not getattr(user, 'is_authenticated', False):
            return drf_error("未登录", status=401)
        try:
            from .models import NoticeRead
            obj, created = NoticeRead.objects.get_or_create(user=user, notice_id=id)
            write_log(request, module='公告', action=f'公告标记已读：{id}', result='success', elapsed_ms=0)
            return drf_ok({"read": True})
        except Exception:
            write_log(request, module='公告', action=f'公告标记已读失败：{id}', result='fail', elapsed_ms=0)
            return drf_error("标记已读失败")

    @action(detail=False, methods=["put", "delete"], url_path=r"(?P<ids>[^/]+)")
    def update_or_delete(self, request, ids: str):
        if request.method.lower() == 'put':
            import time
            t0 = time.perf_counter()
            first_id = ids.split(',')[0]
            try:
                n = Notice.objects.get(pk=first_id)
            except Notice.DoesNotExist:
                write_log(request, module='公告', action=f'更新公告失败：未找到（ID={first_id}）', result='fail', elapsed_ms=int((time.perf_counter()-t0)*1000))
                return drf_error("未找到公告", status=404)
            p = request.data.copy()
            if "title" in p:
                n.title = p.get("title") or n.title
            if "content" in p:
                n.content = p.get("content") or n.content
            if "type" in p:
                n.type = p.get("type") or n.type
            n.save()
            write_log(request, module='公告', action=f'更新公告：{n.title}（ID={n.id}）', result='success', elapsed_ms=int((time.perf_counter()-t0)*1000))
            return drf_ok(self._serialize_detail(n))
        id_list = [i for i in ids.split(',') if i]
        Notice.objects.filter(id__in=id_list).delete()
        write_log(request, module='公告', action=f'删除公告：{ids}', result='success', elapsed_ms=0)
        return drf_ok({}, status=204)


# --- Menus ---
class MenuViewSet(viewsets.ViewSet):
    """菜单与动态路由接口"""

    permission_classes = [MenuPermRequired]

    def get_permissions(self):
        action = getattr(self, 'action', None)
        method = getattr(self.request, 'method', '').upper() if hasattr(self, 'request') else ''
        required = None
        # 查询：列表 list_or_create(GET), tree, form 使用 菜单查询 权限；
        # options 下拉用于角色分配菜单场景，允许具备 菜单查询 或 角色编辑 任一权限访问（OR 逻辑）
        if action in ("list_or_create", "tree", "form") and method == 'GET':
            required = ["sys:menu:query"]
        elif action == "options" and method == 'GET':
            required = ["sys:menu:query", "sys:role:edit"]
        # 新增
        elif action == "list_or_create" and method == 'POST':
            required = ["sys:menu:add"]
        # 更新
        elif action == "update_or_delete" and method == 'PUT':
            required = ["sys:menu:edit"]
        # 删除
        elif action == "update_or_delete" and method == 'DELETE':
            required = ["sys:menu:delete"]
        # routes 接口：用于动态路由加载，需要登录但不强制按钮级菜单权限（前端根据已分配菜单自行构建）
        elif action == "routes":
            required = None
        setattr(self, 'required_perms', required)
        return super().get_permissions()

    @staticmethod
    def _serialize(m: Menu):
        # routeName 仅对“菜单”类型生效（type=2）。目录/按钮/外链在管理列表中不显示路由名称。
        def compute_route_name():
            if m.type != 2:
                return ""
            try:
                if m.route_name:
                    return m.route_name
                if m.component:
                    last = m.component.split('/')[-1]
                    return (last[:1].upper() + last[1:]) if last else f"Menu{m.id}"
                return f"Menu{m.id}"
            except Exception:
                return f"Menu{m.id}"

        return {
            "id": m.id,
            "parentId": m.parent_id,
            "name": m.name,
            "type": m.type,
            "routeName": compute_route_name(),
            "path": m.path,
            "component": m.component,
            "perms": m.perms,
            "icon": m.icon,
            "sort": m.order_num,
            "visible": 1 if m.visible else 0,
            "status": 1 if m.status else 0,
        }

    @staticmethod
    def _build_routes(nodes):
        # 仅目录/菜单生成路由，按钮(3)跳过
        by_parent = {}
        for m in nodes:
            if m.type == 3:
                continue
            pid = m.parent_id or 0
            by_parent.setdefault(pid, []).append(m)

        def build(pid=None):
            result = []
            for m in by_parent.get(pid or 0, []):
                route = {
                    "name": (m.route_name or f"Menu{m.id}"),
                    "path": m.path or (f"/m{m.id}" if m.parent_id is None else m.path or f"m{m.id}"),
                    "component": m.component if m.component else ("Layout" if m.type == 1 else ""),
                    "meta": {
                        "title": m.name,
                        "icon": m.icon or None,
                        "hidden": False if m.visible else True,
                    },
                }
                # 外链型：前端可使用 meta.link 或特殊处理，这里标记，实际消费由前端决定
                if m.type == 4:
                    # 外链菜单：若 path 是绝对 URL，转换为内部占位路径 + meta.link
                    original_path = m.path or ''
                    import re
                    if re.match(r'^https?://', original_path):
                        # 使用稳定且唯一的内部占位路径，避免与其它路由冲突
                        internal_path = f"/ext-{m.id}"
                        route["path"] = internal_path
                        route["component"] = "external/redirect"
                        route["meta"]["link"] = original_path
                    route["meta"]["external"] = True
                children = build(m.id)
                if children:
                    route["children"] = children
                result.append(route)
            return result

        return build(None)

    @action(detail=False, methods=["get"], url_path="routes")
    def routes(self, request):
        user = getattr(request, 'user', None)
        # 全部启用菜单
        all_active = list(Menu.objects.filter(status=True).order_by("order_num", "id"))
        if not user or not getattr(user, 'is_authenticated', False):
            return drf_error("未登录", status=401)
        # 管理员（Django 超级用户 或 角色 code=admin）返回全部
        is_admin_role = False
        try:
            profile = getattr(user, 'profile', None)
            if profile:
                is_admin_role = profile.roles.filter(code='admin').exists()
        except Exception:
            is_admin_role = False
        # 已不再由后端强制插入“文件管理”外链，改为在菜单管理中自行添加外链（type=4）。

        if user.is_superuser or is_admin_role:
            return drf_ok(self._build_routes(all_active))

        # 计算用户角色关联到的菜单，并补齐所有上级目录，保证树结构完整
        role_ids = []
        if profile:
            role_ids = list(profile.roles.values_list('id', flat=True))
        if not role_ids:
            return drf_ok([])
        assigned = list(Menu.objects.filter(status=True, roles__in=role_ids).distinct())
        if not assigned:
            return drf_ok([])
        by_id = {m.id: m for m in all_active}
        selected = {m.id for m in assigned}
        # 向上补全父级
        for m in list(assigned):
            p = m.parent
            while p is not None:
                if p.id in selected:
                    break
                selected.add(p.id)
                p = p.parent
        nodes = [by_id[i] for i in selected if i in by_id]
        nodes.sort(key=lambda x: (x.order_num, x.id))
        return drf_ok(self._build_routes(nodes))

    @action(detail=False, methods=["get", "post"], url_path="")
    def list_or_create(self, request):
        if request.method.lower() == 'get':
            qs = Menu.objects.all().order_by("order_num", "id")
            # 关键字查询：支持 name/path/component/perms
            keyword = request.query_params.get("keyword") or request.query_params.get("keywords")
            if isinstance(keyword, str):
                kw = keyword.strip()
                if kw:
                    qs = qs.filter(
                        Q(name__icontains=kw) |
                        Q(path__icontains=kw) |
                        Q(component__icontains=kw) |
                        Q(perms__icontains=kw)
                    )
            return drf_ok([self._serialize(m) for m in qs])
        # create
        import time
        t0 = time.perf_counter()
        p = request.data.copy()
        m = Menu.objects.create(
            name=p.get("name") or "",
            parent=Menu.objects.filter(pk=p.get("parentId")).first() if p.get("parentId") else None,
            type=int(p.get("type") or 2),
            route_name=p.get("routeName") or "",
            path=p.get("path") or "",
            component=p.get("component") or "",
            perms=p.get("perms") or "",
            icon=p.get("icon") or "",
            order_num=int(p.get("sort") or 0),
            visible=bool(int(p.get("visible", 1))) if isinstance(p.get("visible", 1), (str, int)) else bool(p.get("visible", 1)),
            status=bool(int(p.get("status", 1))) if isinstance(p.get("status", 1), (str, int)) else bool(p.get("status", 1)),
        )
        write_log(request, module='菜单', action=f'新增菜单：{m.name}（ID={m.id}）', result='success', elapsed_ms=int((time.perf_counter()-t0)*1000))
        return drf_ok(self._serialize(m), status=201)

    @action(detail=False, methods=["get"], url_path="options")
    def options(self, request):
        # 返回树形 options（包含目录/菜单/按钮）
        items = list(Menu.objects.filter(status=True).order_by("order_num", "id"))
        by_parent = {}
        for m in items:
            pid = m.parent_id or 0
            by_parent.setdefault(pid, []).append(m)

        def build(pid=None):
            res = []
            for m in by_parent.get(pid or 0, []):
                node = {"label": m.name, "value": m.id}
                children = build(m.id)
                if children:
                    node["children"] = children
                res.append(node)
            return res

        return drf_ok(build(None))

    @action(detail=False, methods=["get"], url_path="tree")
    def tree(self, request):
        # 完整树列表：用于菜单管理树状显示
        items = list(Menu.objects.all().order_by("order_num", "id"))
        by_parent = {}
        for m in items:
            pid = m.parent_id or 0
            by_parent.setdefault(pid, []).append(m)

        def build(pid=None):
            res = []
            for m in by_parent.get(pid or 0, []):
                node = self._serialize(m)
                children = build(m.id)
                if children:
                    node["children"] = children
                res.append(node)
            return res

        return drf_ok(build(None))

    @action(detail=False, methods=["get"], url_path=r"(?P<id>[^/]+)/form")
    def form(self, request, id: str):
        try:
            m = Menu.objects.get(pk=id)
        except Menu.DoesNotExist:
            return drf_error("未找到菜单", status=404)
        return drf_ok(self._serialize(m))

    @action(detail=False, methods=["put", "delete"], url_path=r"(?P<id>[^/]+)")
    def update_or_delete(self, request, id: str):
        if request.method.lower() == 'put':
            import time
            t0 = time.perf_counter()
            try:
                m = Menu.objects.get(pk=id)
            except Menu.DoesNotExist:
                write_log(request, module='菜单', action=f'更新菜单失败：未找到（ID={id}）', result='fail', elapsed_ms=int((time.perf_counter()-t0)*1000))
                return drf_error("未找到菜单", status=404)
            p = request.data.copy()
            # 基本字段
            if "name" in p:
                m.name = p.get("name") or m.name
            if "type" in p:
                try:
                    m.type = int(p.get("type"))
                except Exception:
                    pass
            # 路由名称（前端字段 routeName）
            if "routeName" in p:
                m.route_name = p.get("routeName") or ""
            if "path" in p:
                m.path = p.get("path") or m.path
            if "component" in p:
                m.component = p.get("component") or m.component
            if "perms" in p:
                m.perms = p.get("perms") or m.perms
            if "icon" in p:
                m.icon = p.get("icon") or m.icon
            if "parentId" in p:
                m.parent = Menu.objects.filter(pk=p.get("parentId")).first() if p.get("parentId") else None
            if "sort" in p:
                m.order_num = int(p.get("sort") or 0)
            if "visible" in p:
                s = p.get("visible")
                m.visible = bool(int(s)) if isinstance(s, (str, int)) else bool(s)
            if "status" in p:
                s = p.get("status")
                m.status = bool(int(s)) if isinstance(s, (str, int)) else bool(s)
            m.save()
            write_log(request, module='菜单', action=f'更新菜单：{m.name}（ID={m.id}）', result='success', elapsed_ms=int((time.perf_counter()-t0)*1000))
            return drf_ok(self._serialize(m))
        # delete（支持逗号批量）
        id_list = [i for i in id.split(',') if i]
        Menu.objects.filter(id__in=id_list).delete()
        write_log(request, module='菜单', action=f'删除菜单：{id}', result='success', elapsed_ms=0)
        return drf_ok(status=204)


# --- Logs ---
class LogViewSet(viewsets.ViewSet):
    """操作/访问日志接口"""

    permission_classes = [MenuPermRequired]

    def get_permissions(self):
        action = getattr(self, 'action', None)
        method = getattr(self.request, 'method', '').upper() if hasattr(self, 'request') else ''
        required = None
        # 页面分页列表查看
        if action == 'page' and method == 'GET':
            required = ['sys:log:view']
        # 访问趋势图
        elif action == 'visit_trend' and method == 'GET':
            required = ['sys:log:trend']
        # 访问统计
        elif action == 'visit_stats' and method == 'GET':
            required = ['sys:log:stats']
        setattr(self, 'required_perms', required)
        return super().get_permissions()

    @action(detail=False, methods=["get"], url_path="page")
    def page(self, request):
        qs = OperLog.objects.all().order_by("-id")
        # 关键字（匹配 module/action/operator/ip）
        keywords = request.query_params.get('keywords')
        if keywords:
            qs = qs.filter(
                Q(module__icontains=keywords) |
                Q(action__icontains=keywords) |
                Q(operator__icontains=keywords) |
                Q(ip__icontains=keywords)
            )
        # 时间范围 createTime[]=start&createTime[]=end （YYYY-MM-DD）
        date_range = request.query_params.getlist('createTime[]') or request.query_params.getlist('createTime')
        if date_range and len(date_range) >= 2 and date_range[0] and date_range[1]:
            from datetime import datetime, timedelta
            try:
                start = datetime.strptime(date_range[0], '%Y-%m-%d')
                end = datetime.strptime(date_range[1], '%Y-%m-%d') + timedelta(days=1)
                qs = qs.filter(created_at__gte=start, created_at__lt=end)
            except Exception:
                pass
        total, items, _, _ = paginate_queryset(request, qs)
        # 序列化并进行字段别名转换：created_at -> createTime, elapsed_ms -> executionTime
        raw = OperLogSerializer(items, many=True).data
        # 轻量 UA 解析与 IP 区域判断（避免引入第三方依赖）
        import re
        def parse_browser(ua: str) -> str:
            if not ua:
                return ""
            ua = str(ua)
            try:
                # 顺序很重要：Edge 包含 Chrome 标记，先匹配特定浏览器
                m = re.search(r'Edg/([\d\.]+)', ua)
                if m:
                    return f'Edge {m.group(1)}'
                m = re.search(r'OPR/([\d\.]+)', ua)
                if m:
                    return f'Opera {m.group(1)}'
                m = re.search(r'Chrome/([\d\.]+)', ua)
                if m and 'Chromium' not in ua and 'Edg/' not in ua:
                    return f'Chrome {m.group(1)}'
                m = re.search(r'Firefox/([\d\.]+)', ua)
                if m:
                    return f'Firefox {m.group(1)}'
                # Safari 版本号使用 Version/xx 而非 Safari/xx
                if 'Safari/' in ua and 'Chrome/' not in ua and 'Chromium' not in ua:
                    m = re.search(r'Version/([\d\.]+)', ua)
                    if m:
                        return f'Safari {m.group(1)}'
                    return 'Safari'
            except Exception:
                pass
            return ''

        def parse_os(ua: str) -> str:
            if not ua:
                return ""
            ua = str(ua)
            try:
                # Windows NT 10.0; Win64; x64
                m = re.search(r'Windows NT ([\d\.]+)', ua)
                if m:
                    ver_map = {
                        '10.0': '10/11',  # 10.0 可同时对应 Win10/11，细分需更复杂逻辑
                        '6.3': '8.1',
                        '6.2': '8',
                        '6.1': '7',
                        '6.0': 'Vista',
                        '5.1': 'XP',
                    }
                    ver_raw = m.group(1)
                    ver = ver_map.get(ver_raw, ver_raw)
                    return f'Windows {ver}'
                m = re.search(r'Android ([\d\.]+)', ua)
                if m:
                    return f'Android {m.group(1)}'
                m = re.search(r'iPhone OS ([\d_]+)', ua)
                if m:
                    return f'iOS {m.group(1).replace("_", ".")}'
                m = re.search(r'iPad; CPU OS ([\d_]+)', ua)
                if m:
                    return f'iPadOS {m.group(1).replace("_", ".")}'
                m = re.search(r'Mac OS X ([\d_]+)', ua)
                if m:
                    return f'macOS {m.group(1).replace("_", ".")}'
                if 'Linux' in ua:
                    return 'Linux'
            except Exception:
                pass
            return ''

        def parse_region(ip: str) -> str:
            if not ip:
                return ''
            ip = str(ip)
            try:
                if ip.startswith('127.') or ip == '::1':
                    return '本机'
                # 私有网段
                if ip.startswith('10.') or ip.startswith('192.168.'):
                    return '内网'
                if ip.startswith('172.'):
                    try:
                        seg = int(ip.split('.')[1])
                        if 16 <= seg <= 31:
                            return '内网'
                    except Exception:
                        pass
            except Exception:
                pass
            return '未知'

        data = []
        for r in raw:
            ua = r.get('user_agent')
            ip = r.get('ip')
            data.append({
                'id': r.get('id'),
                'module': r.get('module'),
                'content': r.get('action') or '',
                'operator': r.get('operator'),
                'ip': ip,
                'region': parse_region(ip),
                'browser': parse_browser(ua),
                'os': parse_os(ua),
                'createTime': r.get('created_at'),
                'executionTime': r.get('elapsed_ms'),
            })
        return drf_ok({'total': total, 'list': data})

    @action(detail=False, methods=["get"], url_path="visit-trend")
    def visit_trend(self, request):
        import datetime
        from django.db.models.functions import TruncDate
        from django.db.models import Count
        today = datetime.date.today()
        start_date = today - datetime.timedelta(days=6)
        qs = OperLog.objects.filter(created_at__date__gte=start_date)
        agg = (
            qs.annotate(d=TruncDate("created_at"))
              .values("d")
              .annotate(pv=Count("id"), uv=Count("operator", distinct=True), ip=Count("ip", distinct=True))
              .order_by("d")
        )
        # 构造完整 7 天序列
        date_list = [start_date + datetime.timedelta(days=i) for i in range(7)]
        m = {x["d"]: x for x in agg}
        dates = [d.strftime("%Y-%m-%d") for d in date_list]
        pv_list = [m.get(d, {}).get("pv", 0) for d in date_list]
        uv_list = [m.get(d, {}).get("uv", 0) for d in date_list]
        ip_list = [m.get(d, {}).get("ip", 0) for d in date_list]
        return drf_ok({"dates": dates, "pvList": pv_list, "uvList": uv_list, "ipList": ip_list})

    @action(detail=False, methods=["get"], url_path="visit-stats")
    def visit_stats(self, request):
        import datetime
        from django.db.models import Count
        today = datetime.date.today()
        yesterday = today - datetime.timedelta(days=1)
        # 总计
        total_pv = OperLog.objects.count()
        total_uv = OperLog.objects.aggregate(c=Count("operator", distinct=True))['c'] or 0
        # 今日与昨日
        qs_today = OperLog.objects.filter(created_at__date=today)
        qs_yest = OperLog.objects.filter(created_at__date=yesterday)
        today_pv = qs_today.count()
        today_uv = qs_today.aggregate(c=Count("operator", distinct=True))['c'] or 0
        y_pv = qs_yest.count()
        y_uv = qs_yest.aggregate(c=Count("operator", distinct=True))['c'] or 0
        pv_growth = ((today_pv - y_pv) / y_pv * 100.0) if y_pv else (100.0 if today_pv > 0 else 0.0)
        uv_growth = ((today_uv - y_uv) / y_uv * 100.0) if y_uv else (100.0 if today_uv > 0 else 0.0)
        return drf_ok({
            "todayUvCount": today_uv,
            "totalUvCount": total_uv,
            "uvGrowthRate": round(uv_growth, 2),
            "todayPvCount": today_pv,
            "totalPvCount": total_pv,
            "pvGrowthRate": round(pv_growth, 2),
        })


# --- Dicts ---
class DictViewSet(viewsets.ViewSet):
    """字典与字典项接口"""

    permission_classes = [MenuPermRequired]

    def get_permissions(self):
        action = getattr(self, 'action', None)
        method = getattr(self.request, 'method', '').upper() if hasattr(self, 'request') else ''
        required = None
        # 字典类型分页 / 列表 / 表单 / 字典项分页 / 字典项表单 / 选项 查询权限
        if action in ("page", "list_or_create", "form", "items_page", "item_form") and method == 'GET':
            required = ["sys:dict:query"]
        # 字典项选项接口单独使用 sys:dict:item 更细粒度权限（仅访问字典数据，不必具备字典类型查询权限）
        elif action == "item_options" and method == 'GET':
            required = ["sys:dict:item"]
        # 字典类型新增
        elif action == "list_or_create" and method == 'POST':
            required = ["sys:dict:add"]
        # 字典类型更新
        elif action == "update_or_delete" and method == 'PUT':
            required = ["sys:dict:edit"]
        # 字典类型删除
        elif action == "update_or_delete" and method == 'DELETE':
            required = ["sys:dict:delete"]
        # 字典项新增
        elif action == "items_list_or_create" and method == 'POST':
            required = ["sys:dict:add"]
        # 字典项更新
        elif action == "item_update_or_delete" and method == 'PUT':
            required = ["sys:dict:edit"]
        # 字典项删除
        elif action == "item_update_or_delete" and method == 'DELETE':
            required = ["sys:dict:delete"]
        setattr(self, 'required_perms', required)
        return super().get_permissions()

    @action(detail=False, methods=["get"], url_path="page")
    def page(self, request):
        # pageNum/pageSize/keywords
        qs = DictType.objects.all().order_by("id")
        kw = request.query_params.get("keywords")
        if kw:
            qs = qs.filter(Q(name__icontains=kw) | Q(code__icontains=kw))
        total, items, _, _ = paginate_queryset(request, qs)
        data = DictTypeSerializer(items, many=True).data
        # 统一将 status 转换为 1/0，避免前端严格比较 === 1 时被识别为禁用
        for d in data:
            # d['status'] 可能是 True/False
            try:
                d['status'] = 1 if d.get('status') else 0
            except Exception:
                d['status'] = 0
        return drf_ok({"total": total, "list": data})

    @action(detail=False, methods=["get", "post"], url_path="")
    def list_or_create(self, request):
        if request.method.lower() == 'get':
            items = DictType.objects.all().order_by("id")
            data = [{"id": d.id, "name": d.name, "dictCode": d.code, "status": 1 if d.status else 0} for d in items]
            return drf_ok(data)
        # create
        import time
        t0 = time.perf_counter()
        payload = request.data.copy()
        name = payload.get("name")
        code = payload.get("dictCode") or payload.get("code")
        status_raw = payload.get("status", 1)
        def parse_status(v, default=True):
            if v in (None, "", "null"):
                return default
            if isinstance(v, (str, int)):
                try:
                    return bool(int(v))
                except Exception:
                    return default
            return bool(v)
        dt = DictType.objects.create(name=name or "", code=code or "", status=parse_status(status_raw, True))
        write_log(request, module='字典', action=f'新增字典：{dt.code}（{dt.name}，ID={dt.id}）', result='success', elapsed_ms=int((time.perf_counter()-t0)*1000))
        return drf_ok({"id": dt.id}, status=201)

    @action(detail=False, methods=["get"], url_path=r"(?P<id>[^/]+)/form")
    def form(self, request, id: str):
        try:
            d = DictType.objects.get(pk=id)
        except DictType.DoesNotExist:
            return drf_error("未找到字典", status=404)
        return drf_ok({"id": d.id, "name": d.name, "dictCode": d.code, "status": 1 if d.status else 0})

    @action(detail=False, methods=["put", "delete"], url_path=r"(?P<ids>[^/]+)")
    def update_or_delete(self, request, ids: str):
        if request.method.lower() == 'put':
            first_id = ids.split(',')[0]
            try:
                d = DictType.objects.get(pk=first_id)
            except DictType.DoesNotExist:
                return drf_error("未找到字典", status=404)
            payload = request.data.copy()
            if "name" in payload:
                d.name = payload.get("name") or d.name
            if "dictCode" in payload or "code" in payload:
                d.code = payload.get("dictCode") or payload.get("code") or d.code
            if "status" in payload:
                s = payload.get("status")
                def parse_status(v, default=d.status):
                    if v in (None, "", "null"):
                        return default
                    if isinstance(v, (str, int)):
                        try:
                            return bool(int(v))
                        except Exception:
                            return default
                    return bool(v)
                d.status = parse_status(s, d.status)
            d.save()
            write_log(request, module='字典', action=f'更新字典：{d.code}（{d.name}，ID={d.id}）', result='success', elapsed_ms=0)
            return drf_ok({"id": d.id})
        id_list = [i for i in ids.split(',') if i]
        DictType.objects.filter(id__in=id_list).delete()
        write_log(request, module='字典', action=f'删除字典：{ids}', result='success', elapsed_ms=0)
        return drf_ok(status=204)

    # dict items
    @action(detail=False, methods=["get", "post"], url_path=r"(?P<dict_code>[^/]+)/items")
    def items_list_or_create(self, request, dict_code: str):
        try:
            dt = DictType.objects.get(code=dict_code)
        except DictType.DoesNotExist:
            return drf_error("未找到字典", status=404)
        # 若字典类型被禁用，阻止访问或创建其字典项
        if not dt.status:
            return drf_error("字典已禁用", status=403)
        if request.method.lower() == 'get':
            items = DictItem.objects.filter(dict_type=dt).order_by("sort", "id")
            data = DictItemSerializer(items, many=True).data
            return drf_ok(data)
        # create item
        import time
        t0 = time.perf_counter()
        payload = request.data.copy()
        i = DictItem.objects.create(
            dict_type=dt,
            label=payload.get("label") or "",
            value=payload.get("value") or "",
            sort=int(payload.get("sort") or 0),
            status=(lambda v: (False if v in ("0", 0) else True) if v not in (None, "", "null") else True)(payload.get("status", 1)),
            tag_type=payload.get("tagType") or payload.get("tag_type") or "",
        )
        write_log(request, module='字典', action=f'新增字典项：{dt.code} -> {i.label}（ID={i.id}）', result='success', elapsed_ms=int((time.perf_counter()-t0)*1000))
        return drf_ok({"id": i.id}, status=201)

    @action(detail=False, methods=["get"], url_path=r"(?P<dict_code>[^/]+)/items/page")
    def items_page(self, request, dict_code: str):
        try:
            dt = DictType.objects.get(code=dict_code)
        except DictType.DoesNotExist:
            return drf_error("未找到字典", status=404)
        if not dt.status:
            return drf_error("字典已禁用", status=403)
        qs = DictItem.objects.filter(dict_type=dt).order_by("sort", "id")
        kw = request.query_params.get("keywords")
        if kw:
            qs = qs.filter(Q(label__icontains=kw) | Q(value__icontains=kw))
        total, items, _, _ = paginate_queryset(request, qs)
        data = DictItemSerializer(items, many=True).data
        # 兜底：若序列化器未生效或其他来源数据，确保 status 数值化
        for it in data:
            try:
                it["status"] = 1 if it.get("status") in (True, 1, "1", "true", "True") else 0
            except Exception:
                it["status"] = 0
        return drf_ok({"total": total, "list": data})

    @action(detail=False, methods=["get"], url_path=r"(?P<dict_code>[^/]+)/items/(?P<item_id>[^/]+)/form")
    def item_form(self, request, dict_code: str, item_id: str):
        try:
            dt = DictType.objects.get(code=dict_code)
        except DictType.DoesNotExist:
            return drf_error("未找到字典", status=404)
        if not dt.status:
            return drf_error("字典已禁用", status=403)
        try:
            i = DictItem.objects.get(pk=item_id, dict_type=dt)
        except DictItem.DoesNotExist:
            return drf_error("未找到字典项", status=404)
        return drf_ok({"id": i.id, "label": i.label, "value": i.value, "status": 1 if i.status else 0, "sort": i.sort, "tagType": getattr(i, 'tag_type', '')})

    @action(detail=False, methods=["get"], url_path=r"(?P<dict_code>[^/]+)/items/options")
    def item_options(self, request, dict_code: str):
        try:
            dt = DictType.objects.get(code=dict_code)
            if not dt.status:
                return drf_ok([])  # 禁用字典返回空选项，避免表单误用
            items = DictItem.objects.filter(dict_type=dt, status=True).order_by("sort", "id")
            data = [{"label": i.label, "value": i.value} for i in items]
            return drf_ok(data)
        except DictType.DoesNotExist:
            # 内置兜底：常用字典 gender 缺失时返回默认选项
            if dict_code == 'gender':
                return drf_ok([
                    {"label": "男", "value": 1},
                    {"label": "女", "value": 2},
                    {"label": "保密", "value": 0},
                ])
            return drf_error("未找到字典", status=404)

    @action(detail=False, methods=["put", "delete"], url_path=r"(?P<dict_code>[^/]+)/items/(?P<item_id>[^/]+)")
    def item_update_or_delete(self, request, dict_code: str, item_id: str):
        try:
            dt = DictType.objects.get(code=dict_code)
        except DictType.DoesNotExist:
            return drf_error("未找到字典", status=404)
        if not dt.status:
            return drf_error("字典已禁用", status=403)
        if request.method.lower() == 'put':
            try:
                i = DictItem.objects.get(pk=item_id, dict_type=dt)
            except DictItem.DoesNotExist:
                return drf_error("未找到字典项", status=404)
            payload = request.data.copy()
            if "label" in payload:
                i.label = payload.get("label") or i.label
            if "value" in payload:
                i.value = payload.get("value") or i.value
            if "sort" in payload:
                i.sort = int(payload.get("sort") or 0)
            if "status" in payload:
                s = payload.get("status")
                if s in (None, "", "null"):
                    pass  # 忽略空值，不修改
                else:
                    try:
                        i.status = bool(int(s))
                    except Exception:
                        i.status = True if s else i.status
            if "tagType" in payload or "tag_type" in payload:
                tv = payload.get("tagType") or payload.get("tag_type")
                i.tag_type = tv or ""
            i.save()
            write_log(request, module='字典', action=f'更新字典项：{dt.code} -> {i.label}（ID={i.id}）', result='success', elapsed_ms=0)
            return drf_ok({"id": i.id})
        # delete supports ids path, but this endpoint targets single id by design; handle multi-ids too
        id_list = [i for i in item_id.split(',') if i]
        DictItem.objects.filter(dict_type=dt, id__in=id_list).delete()
        write_log(request, module='字典', action=f'删除字典项：{dt.code} -> {item_id}', result='success', elapsed_ms=0)
        return drf_ok(status=204)


# --- Depts ---
class DeptViewSet(viewsets.ViewSet):
    """部门管理接口"""
    permission_classes = [MenuPermRequired]

    def get_permissions(self):
        action = getattr(self, 'action', None)
        method = getattr(self.request, 'method', '').upper() if hasattr(self, 'request') else ''
        required = None
        # 查询相关：列表、树、下拉、表单
        if action in ("list_or_create", "tree", "options", "form") and method == 'GET':
            required = ["sys:dept:query"]
        # 新增
        elif action == "list_or_create" and method == 'POST':
            required = ["sys:dept:add"]
        # 更新
        elif action == "update_or_delete" and method == 'PUT':
            required = ["sys:dept:edit"]
        # 删除
        elif action == "update_or_delete" and method == 'DELETE':
            required = ["sys:dept:delete"]
        setattr(self, 'required_perms', required)
        return super().get_permissions()

    def _build_tree(self, nodes):
        by_parent = {}
        for d in nodes:
            pid = d.parent_id or 0
            by_parent.setdefault(pid, []).append(d)

        def build(pid=None, path=None):
            if path is None:
                path = set()
            res = []
            for d in by_parent.get(pid or 0, []):
                if d.id in path:
                    continue
                new_path = set(path)
                new_path.add(d.id)
                item = {
                    "id": d.id,
                    "parentId": d.parent_id,
                    "name": d.name,
                    "code": getattr(d, 'code', ''),
                    "status": 1 if d.status else 0,
                    "sort": d.order_num,
                    "children": build(d.id, new_path),
                }
                res.append(item)
            return res

        return build(None)

    @action(detail=False, methods=["get", "post"], url_path="")
    def list_or_create(self, request):
        if request.method.lower() == 'get':
            qs = Department.objects.all().order_by("order_num", "id")
            # 关键字：name/code 模糊
            keyword = request.query_params.get("keyword") or request.query_params.get("keywords")
            if isinstance(keyword, str):
                kw = keyword.strip()
                if kw:
                    qs = qs.filter(Q(name__icontains=kw) | Q(code__icontains=kw))
            # 状态过滤：1/0
            status_val = request.query_params.get("status")
            if status_val is not None and status_val != "":
                try:
                    qs = qs.filter(status=bool(int(status_val)))
                except Exception:
                    pass
            data = DeptSerializer(qs, many=True).data
            return drf_ok(data)
        import time
        t0 = time.perf_counter()
        payload = request.data.copy()
        name = payload.get("name")
        parent_id = payload.get("parentId")
        sort = payload.get("sort", 0)
        status = payload.get("status", 1)
        code = payload.get("code", "")
        dept = Department.objects.create(
            name=name or "",
            parent=Department.objects.filter(pk=parent_id).first() if parent_id else None,
            order_num=int(sort or 0),
            code=code or "",
            status=bool(int(status)) if isinstance(status, (str, int)) else bool(status),
        )
        write_log(request, module='部门', action=f'新增部门：{dept.name}（ID={dept.id}）', result='success', elapsed_ms=int((time.perf_counter()-t0)*1000))
        return drf_ok({"id": dept.id}, status=201)

    @action(detail=False, methods=["get"], url_path="tree")
    def tree(self, request):
        try:
            qs = Department.objects.all().order_by("order_num", "id")
            return drf_ok(self._build_tree(list(qs)))
        except Exception as e:
            write_log(request, module='部门', action=f'查询部门树失败：{e}', result='fail', elapsed_ms=0)
            return drf_error("服务器内部错误", status=500)

    @action(detail=False, methods=["get"], url_path="options")
    def options(self, request):
        qs = Department.objects.filter(status=True).order_by("order_num", "id")
        data = [
            {"label": d.name, "value": d.id}
            for d in qs
        ]
        return drf_ok(data)

    @action(detail=False, methods=["get"], url_path=r"(?P<id>[^/]+)/form")
    def form(self, request, id: str):
        try:
            d = Department.objects.get(pk=id)
        except Department.DoesNotExist:
            return drf_error("未找到部门", status=404)
        return drf_ok({
            "id": d.id, "name": d.name, "code": getattr(d, 'code', ''), "parentId": d.parent_id, "status": 1 if d.status else 0, "sort": d.order_num
        })

    @action(detail=False, methods=["put", "delete"], url_path=r"(?P<ids>[^/]+)")
    def update_or_delete(self, request, ids: str):
        if request.method.lower() == 'put':
            first_id = ids.split(',')[0]
            try:
                d = Department.objects.get(pk=first_id)
            except Department.DoesNotExist:
                return drf_error("未找到部门", status=404)
            payload = request.data.copy()
            d.name = payload.get("name", d.name)
            parent_id = payload.get("parentId")
            # 校验：禁止将上级设置为自身或其子孙，避免循环
            if parent_id:
                try:
                    pid_int = int(parent_id)
                except Exception:
                    pid_int = None
                if pid_int and pid_int == d.id:
                    return drf_error("上级部门不能为自身", status=400)
                new_parent = Department.objects.filter(pk=parent_id).first()
                cur = new_parent
                while cur is not None:
                    if cur.id == d.id:
                        return drf_error("上级部门不能为其子孙节点", status=400)
                    cur = cur.parent
                d.parent = new_parent
            else:
                d.parent = None
            if "sort" in payload:
                d.order_num = int(payload.get("sort") or 0)
            if "code" in payload:
                d.code = payload.get("code") or ""
            if "status" in payload:
                s = payload.get("status")
                d.status = bool(int(s)) if isinstance(s, (str, int)) else bool(s)
            d.save()
            write_log(request, module='部门', action=f'更新部门：{d.name}（ID={d.id}）', result='success', elapsed_ms=0)
            return drf_ok({"id": d.id})
        id_list = [i for i in ids.split(',') if i]
        Department.objects.filter(id__in=id_list).delete()
        write_log(request, module='部门', action=f'删除部门：{ids}', result='success', elapsed_ms=0)
        return drf_ok(status=204)


# --- Configs ---
class ConfigViewSet(viewsets.ViewSet):
    """参数配置接口

    按钮级权限映射：
    - 查询: sys:config:query -> page / list_or_create(GET) / form
    - 新增: sys:config:add   -> list_or_create(POST)
    - 编辑: sys:config:edit  -> update_or_delete(PUT)
    - 删除: sys:config:delete-> update_or_delete(DELETE)
    刷新缓存暂归入查询权限（需要看到菜单即可）。
    """

    permission_classes = [MenuPermRequired]

    def get_permissions(self):
        action = getattr(self, 'action', None)
        method = getattr(self.request, 'method', '').upper() if hasattr(self, 'request') else ''
        required = None
        if action in ('page', 'form') or (action == 'list_or_create' and method == 'GET'):
            required = ['sys:config:query']
        elif action == 'list_or_create' and method == 'POST':
            required = ['sys:config:add']
        elif action == 'update_or_delete' and method == 'PUT':
            required = ['sys:config:edit']
        elif action == 'update_or_delete' and method == 'DELETE':
            required = ['sys:config:delete']
        elif action == 'refresh_cache':
            required = ['sys:config:query']
        setattr(self, 'required_perms', required)
        return super().get_permissions()

    @staticmethod
    def _serialize(conf: Config):
        return {
            "id": conf.id,
            "configName": conf.key,  # 简化：使用 key 作为名称
            "configKey": conf.key,
            "configValue": conf.value,
            "status": 1 if conf.status else 0,
            "remark": conf.remark,
        }

    @action(detail=False, methods=["get"], url_path="page")
    def page(self, request):
        qs = Config.objects.all().order_by("id")
        kw = request.query_params.get("keywords")
        if kw:
            qs = qs.filter(Q(key__icontains=kw) | Q(value__icontains=kw))
        total, items, _, _ = paginate_queryset(request, qs)
        data = [self._serialize(c) for c in items]
        write_log(request, module='参数', action=f'查询参数分页：{total} 条', result='success', elapsed_ms=0)
        return drf_ok({"total": total, "list": data})

    @action(detail=False, methods=["get", "post"], url_path="")
    def list_or_create(self, request):
        if request.method.lower() == 'get':
            items = Config.objects.all().order_by("id")
            write_log(request, module='参数', action=f'查询参数列表：{len(items)} 条', result='success', elapsed_ms=0)
            return drf_ok([self._serialize(c) for c in items])
        import time
        t0 = time.perf_counter()
        p = request.data.copy()
        key = p.get("configKey") or p.get("key") or p.get("configName")
        value = p.get("configValue") or p.get("value") or ""
        remark = p.get("remark") or ""
        status = p.get("status", 1)
        c = Config.objects.create(key=key or "", value=value, remark=remark, status=bool(int(status)) if isinstance(status, (str, int)) else bool(status))
        write_log(request, module='参数', action=f'新增参数：{c.key}（ID={c.id}）', result='success', elapsed_ms=int((time.perf_counter()-t0)*1000))
        return drf_ok(self._serialize(c), status=201)

    @action(detail=False, methods=["get"], url_path=r"(?P<id>[^/]+)/form")
    def form(self, request, id: str):
        try:
            c = Config.objects.get(pk=id)
        except Config.DoesNotExist:
            return drf_error("未找到参数", status=404)
        write_log(request, module='参数', action=f'查看参数表单：{c.key}（ID={c.id}）', result='success', elapsed_ms=0)
        return drf_ok(self._serialize(c))

    @action(detail=False, methods=["put", "delete"], url_path=r"(?P<ids>[^/]+)")
    def update_or_delete(self, request, ids: str):
        if request.method.lower() == 'put':
            first_id = ids.split(',')[0]
            try:
                c = Config.objects.get(pk=first_id)
            except Config.DoesNotExist:
                return drf_error("未找到参数", status=404)
            p = request.data.copy()
            if "configKey" in p or "key" in p or "configName" in p:
                c.key = p.get("configKey") or p.get("key") or p.get("configName") or c.key
            if "configValue" in p or "value" in p:
                c.value = p.get("configValue") or p.get("value") or c.value
            if "remark" in p:
                c.remark = p.get("remark") or c.remark
            if "status" in p:
                s = p.get("status")
                c.status = bool(int(s)) if isinstance(s, (str, int)) else bool(s)
            c.save()
            write_log(request, module='参数', action=f'更新参数：{c.key}（ID={c.id}）', result='success', elapsed_ms=0)
            return drf_ok(self._serialize(c))
        id_list = [i for i in ids.split(',') if i]
        Config.objects.filter(id__in=id_list).delete()
        write_log(request, module='参数', action=f'删除参数：{ids}', result='success', elapsed_ms=0)
        return drf_ok(status=204)

    @action(detail=False, methods=["post"], url_path="refresh-cache")
    def refresh_cache(self, request):
        write_log(request, module='参数', action='刷新参数缓存', result='success', elapsed_ms=0)
        return drf_ok({"message": "refreshed"})


# --- Codegen (占位实现以满足前端路由，不做真正代码生成) ---
class CodegenViewSet(viewsets.ViewSet):
    """代码生成占位接口

    前端依赖这些路径存在；这里返回最小可用的占位数据，避免 404。
    """

    def table_page(self, request):
        # 支持基本分页参数，返回空列表
        try:
            page_num = int(request.query_params.get("pageNum", 1))
            page_size = int(request.query_params.get("pageSize", 10))
        except Exception:
            page_num, page_size = 1, 10
        return drf_ok({"total": 0, "list": []})

    def config(self, request, table_name: str):
        # GET: 返回占位配置；POST: 保存占位；DELETE: 删除占位
        method = request.method.lower()
        if method == 'get':
            data = {
                "tableName": table_name,
                "comment": f"{table_name} table",
                "columns": [],
                "author": "admin",
            }
            return drf_ok(data)
        if method == 'post':
            return drf_ok({"saved": True})
        if method == 'delete':
            return drf_ok(status=204)
        return drf_error("不支持的方法", status=405)

    def preview(self, request, table_name: str):
        # 返回一个简单的文件预览映射（占位）
        files = {
            "models.py": f"# preview model for {table_name}\n",
            "views.py": f"# preview view for {table_name}\n",
        }
        return drf_ok(files)

    def download(self, request, table_name: str):
        # 简化为返回文本附件，避免压缩打包复杂度
        content = f"# codegen package for {table_name}\n"
        resp = HttpResponse(content, content_type="text/plain")
        resp["Content-Disposition"] = f"attachment; filename={table_name}_codegen.txt"
        return resp


def root_index(request):  # pragma: no cover
    return drf_ok({"name": "api_v1"})


# --- Crawler Conf (开放接口，无需认证) ---
class CrawlerConfViewSet(viewsets.ViewSet):
    """数据采集节点配置（对外开放，无需认证）

    路由：
    - GET /crawler/conf -> 列表
    - POST /crawler/conf -> 新增
    - GET /crawler/conf/<id>/form -> 获取表单数据
    - PUT /crawler/conf/<ids> -> 更新（多个 id 传入逗号，以第一个为目标）
    - DELETE /crawler/conf/<ids> -> 删除
    """

    def get_permissions(self):
        """权限策略：
        - GET 请求（列表/表单）对外开放 AllowAny
        - 写操作（POST/PUT/DELETE）需要登录 IsAuthenticated
        """
        method = getattr(self.request, 'method', '').upper() if hasattr(self, 'request') else ''
        if method == 'GET':
            return [AllowAny()]
        return [IsAuthenticated()]

    @action(detail=False, methods=["get", "post"], url_path="")
    def list_or_create(self, request):
        if request.method.lower() == 'get':
            qs = CrawlerConf.objects.all().order_by("order_num", "id")
            # 支持关键字搜索，匹配服务器名称或节点
            kw = request.query_params.get('keywords') or request.query_params.get('keyword')
            if kw:
                qs = qs.filter(Q(server_name__icontains=kw) | Q(node__icontains=kw))
            # 支持两种返回格式：
            # - 若前端传入分页参数（pageNum/pageSize），返回 {total, list}
            # - 否则返回数组以匹配部分旧前端组件的期望
            total, items, _, _ = paginate_queryset(request, qs)
            data = CrawlerConfSerializer(items, many=True).data
            if request.query_params.get('pageNum') or request.query_params.get('page'):
                return drf_ok({"total": total, "list": data})
            return drf_ok(data)
        # create
        import time
        t0 = time.perf_counter()
        payload = request.data or {}
        conf = CrawlerConf.objects.create(
            server_name=payload.get('server_name', '') or payload.get('serverName', ''),
            node=payload.get('node', ''),
            ip=payload.get('ip', ''),
            status=int(payload.get('status', 1)),
            order_num=int(payload.get('order_num', 0) or payload.get('orderNum', 0)),
        )
        write_log(request, module='数据采集', action=f'新增节点：{conf.server_name}（ID={conf.id}）', result='success', elapsed_ms=int((time.perf_counter()-t0)*1000))
        return drf_ok(CrawlerConfSerializer(conf).data, status=201)


class CrawlerLogViewSet(viewsets.ViewSet):
    """爬虫日志（开放式接口）：允许任何人提交与查询日志，用于采集/调试场景。

    - GET  /crawler/logs/page -> 分页查询，支持 keywords（匹配日志内容）、createTime 日期范围
    - GET  /crawler/logs -> 列表（非分页）
    - POST /crawler/logs -> 新增日志（接受 module, action/content, result/level, elapsed_ms, operator, ip, user_agent）
    """

    def get_permissions(self):
        # 对所有动作均开放（AllowAny）
        return [AllowAny()]

    @action(detail=False, methods=["get"], url_path="page")
    def page(self, request):
        try:
            from .models import CrawlerLog
            qs = CrawlerLog.objects.all().order_by("-id")
            # 关键字仅匹配日志内容（action）
            keywords = request.query_params.get('keywords') or request.query_params.get('keyword')
            if keywords:
                qs = qs.filter(Q(content__icontains=keywords))

            # 时间范围 createTime[]=start&createTime[]=end （YYYY-MM-DD）
            date_range = request.query_params.getlist('createTime[]') or request.query_params.getlist('createTime')
            if date_range and len(date_range) >= 2 and date_range[0] and date_range[1]:
                from datetime import datetime, timedelta
                try:
                    start = datetime.strptime(date_range[0], '%Y-%m-%d')
                    end = datetime.strptime(date_range[1], '%Y-%m-%d') + timedelta(days=1)
                    qs = qs.filter(created_at__gte=start, created_at__lt=end)
                except Exception:
                    pass

            total, items, _, _ = paginate_queryset(request, qs)
            raw = CrawlerLogSerializer(items, many=True).data
            data = []
            for r in raw:
                data.append({
                    'id': r.get('id'),
                    'createTime': r.get('created_at'),
                    'level': r.get('level'),
                    'module': r.get('module'),
                    'content': r.get('content') or '',
                    'executionTime': r.get('elapsed_ms'),
                })
            return drf_ok({'total': total, 'list': data})
        except Exception as e:
            return drf_error('服务器内部错误', status=500, data={'msg': str(e)})

    @action(detail=False, methods=["get"], url_path="")
    def list_or_create(self, request):
        # GET 列表（非分页）
        if request.method.lower() == 'get':
            from .models import CrawlerLog
            qs = CrawlerLog.objects.all().order_by('-id')
            raw = CrawlerLogSerializer(qs, many=True).data
            data = []
            for r in raw:
                data.append({
                    'id': r.get('id'),
                    'createTime': r.get('created_at'),
                    'level': r.get('level'),
                    'module': r.get('module'),
                    'content': r.get('content') or '',
                    'executionTime': r.get('elapsed_ms'),
                })
            return drf_ok(data)

        # POST 创建日志
        import time
        t0 = time.perf_counter()
        p = request.data or {}
        try:
            payload = {
                'module': p.get('module') or p.get('模块') or p.get('mod') or '',
                'content': p.get('content') or p.get('action') or p.get('日志内容') or '',
                'level': (p.get('level') or p.get('result') or p.get('日志级别')) or 'info',
                'elapsed_ms': int(p.get('executionTime') or p.get('elapsed_ms') or p.get('模块耗时') or 0),
                'operator': p.get('operator') or p.get('操作人') or '',
                'ip': p.get('ip') or p.get('IP') or '',
                'user_agent': p.get('user_agent') or p.get('userAgent') or '',
            }
            s = CrawlerLogSerializer(data=payload)
            s.is_valid(raise_exception=True)
            obj = s.save()
            # 兼容：若传入 created_at，则尝试更新该字段
            created_at = p.get('created_at') or p.get('createTime') or None
            if created_at:
                try:
                    from datetime import datetime
                    fmt = '%Y-%m-%d %H:%M:%S' if (len(str(created_at)) > 10 and ':' in str(created_at)) else '%Y-%m-%d'
                    dt = datetime.strptime(str(created_at), fmt)
                    obj.created_at = dt
                    obj.save(update_fields=['created_at'])
                except Exception:
                    pass
            write_log(request, module='爬虫日志', action=f'新增日志：{payload.get("module")}', result='success', elapsed_ms=int((time.perf_counter()-t0)*1000))
            return drf_ok({'id': obj.id}, status=201)
        except Exception as e:
            write_log(request, module='爬虫日志', action=f'新增日志失败', result='fail', elapsed_ms=0)
            return drf_error('创建日志失败', status=400, data={'msg': str(e)})

    @action(detail=False, methods=["get"], url_path=r"(?P<id>[^/]+)/form")
    def form(self, request, id: str):
        try:
            conf = CrawlerConf.objects.get(pk=id)
        except CrawlerConf.DoesNotExist:
            return drf_error("未找到配置", status=404)
        return drf_ok(CrawlerConfSerializer(conf).data)

    @action(detail=False, methods=["put", "delete"], url_path=r"(?P<ids>[^/]+)")
    def update_or_delete(self, request, ids: str):
        if request.method.lower() == 'put':
            first_id = ids.split(',')[0]
            try:
                conf = CrawlerConf.objects.get(pk=first_id)
            except CrawlerConf.DoesNotExist:
                return drf_error("未找到配置", status=404)
            p = request.data or {}
            if 'server_name' in p or 'serverName' in p:
                conf.server_name = p.get('server_name') or p.get('serverName') or conf.server_name
            if 'node' in p:
                conf.node = p.get('node') or conf.node
            if 'ip' in p:
                conf.ip = p.get('ip') or conf.ip
            if 'status' in p:
                try:
                    conf.status = int(p.get('status'))
                except Exception:
                    conf.status = 1
            if 'order_num' in p or 'orderNum' in p:
                try:
                    conf.order_num = int(p.get('order_num') or p.get('orderNum') or conf.order_num)
                except Exception:
                    pass
            conf.save()
            write_log(request, module='数据采集', action=f'更新节点：{conf.server_name}（ID={conf.id}）', result='success', elapsed_ms=0)
            return drf_ok(CrawlerConfSerializer(conf).data)
        # delete
        id_list = [i for i in ids.split(',') if i]
        CrawlerConf.objects.filter(id__in=id_list).delete()
        write_log(request, module='数据采集', action=f'删除节点：{ids}', result='success', elapsed_ms=0)
        return drf_ok(status=204)


# --- Crawler Category (类目采集) ---
def _extract_cloud_items():
    try:
        return list(DictItem.objects.filter(dict_type__code__in=["cloud_type", "clooud_type"], status=True))
    except Exception:
        return []


def _resolve_site_and_repo(cat_site=None):
    """解析字典中的 Seafile site 与 repo_id，返回 (base_site, repo_id, err_msg)

    如果未找到会返回 (None, None, str_err)
    """
    items = _extract_cloud_items()
    site = None
    repo_id = None
    try:
        if items:
            # 首先尝试从 label/value 中找到 site
            for it in items:
                try:
                    lab = (it.label or "").lower()
                    val = (it.value or "").strip()
                except Exception:
                    continue
                if not site and ("site" in lab or "站" in lab or val.startswith("http")):
                    site = val
            # 若未找到 site，尝试解析第一个 value 为 JSON
            if (not site) and items[0] and items[0].value:
                try:
                    j = json.loads(items[0].value)
                    site = site or j.get("site") or j.get("url") or j.get("host") or j.get("endpoint")
                except Exception:
                    pass

            # 定位 repo_id：优先精确 label
            exact_labels = {"资料库id", "资料库 id", "资料库ID", "repo id", "repoid", "repository id"}
            for it in items:
                try:
                    lab = (it.label or "").strip()
                    val = (it.value or "").strip()
                except Exception:
                    continue
                if lab in exact_labels:
                    repo_id = val
                    break
            # 若仍未找到，尝试匹配与 cat_site 相同的 label/value
            if not repo_id and cat_site:
                for it in items:
                    try:
                        lab = (it.label or "").strip()
                        val = (it.value or "").strip()
                    except Exception:
                        continue
                    if lab == str(cat_site).strip() or val == str(cat_site).strip():
                        repo_id = val
                        break
            # 解析 JSON 中的 repo 字段
            if not repo_id:
                for it in items:
                    try:
                        v = (it.value or "").strip()
                        j = json.loads(v)
                        for k in ("repo", "repo_id", "repoid", "repository", "repository_id"):
                            if j.get(k):
                                repo_id = str(j.get(k))
                                break
                        if repo_id:
                            break
                    except Exception:
                        continue
            # fallback: 若仅一项且 value 看起来不像 URL，则使用其 value
            if not repo_id and len(items) == 1:
                try:
                    v = (items[0].value or "").strip()
                    if v and not re.match(r"^https?://", v, re.I):
                        repo_id = v
                except Exception:
                    pass
    except Exception:
        pass

    if not site:
        return None, None, "未在字典中配置 Seafile 站点 (cloud_type)，请先配置 site"
    if not repo_id:
        return None, None, "未在字典中定位到资料库 ID (repo id)，请检查 cloud_type 字典项"

    base_site = str(site).strip()
    if not re.match(r"^https?://", base_site, re.I):
        base_site = "https://" + base_site
    return base_site, repo_id, None


def _build_paths(cat, t):
    """根据类目对象和时间构建 folder, file_name, p_raw, view_path_parts"""
    folder = str(cat.site or '').strip('/')
    file_name = f"{cat.category_id}_{cat.site}.xlsx"
    p_raw = f"/爬虫数据/{folder}/{t}/{file_name}"
    view_path_parts = ["爬虫数据", folder, t, file_name]
    return folder, file_name, p_raw, view_path_parts


def _make_urls(base_site, repo_id, p_raw, view_path_parts):
    """返回 (download_url, view_url) 两个外链"""
    try:
        download_url = base_site.rstrip('/') + f"/api2/repos/{quote(repo_id)}/file/?p={quote(p_raw)}"
    except Exception:
        download_url = None
    try:
        view_path = "/".join([quote(p) for p in view_path_parts])
        view_url = base_site.rstrip('/') + f"/lib/{quote(repo_id)}/file/{view_path}"
    except Exception:
        view_url = None
    return download_url, view_url

class CrawlerCategoryViewSet(viewsets.ViewSet):
    """爬取类目的分页与 CRUD

    - GET /crawler/category/page -> 分页返回 {total, list}
    - GET /crawler/category -> 列表（数组）
    - POST /crawler/category -> 新增（需认证）
    - GET /crawler/category/<id>/form -> 单项
    - PUT/DELETE /crawler/category/<ids> -> 更新/删除（需认证）
    """

    def get_permissions(self):
        method = getattr(self.request, 'method', '').upper() if hasattr(self, 'request') else ''
        if method == 'GET':
            return [AllowAny()]
        return [IsAuthenticated()]

    @action(detail=False, methods=["get"], url_path="page")
    def page(self, request):
        qs = CrawlerCategory.objects.all().order_by("-created_at", "id")
        # 支持关键字搜索，匹配类目名或类目ID
        kw = request.query_params.get('keywords') or request.query_params.get('keyword')
        if kw:
            try:
                k = str(kw).strip()
                if k:
                    qs = qs.filter(Q(name__icontains=k) | Q(category_id__icontains=k))
            except Exception:
                pass
        # 支持按类目站点过滤（site 精确匹配）
        site_q = request.query_params.get('site') or request.query_params.get('siteName')
        if site_q:
            try:
                s = str(site_q).strip()
                if s:
                    qs = qs.filter(site__iexact=s)
            except Exception:
                pass
        total, items, _, _ = paginate_queryset(request, qs)
        data = CrawlerCategorySerializer(items, many=True).data
        return drf_ok({"total": total, "list": data})

    @action(detail=False, methods=["get", "post"], url_path="")
    def list_or_create(self, request):
        if request.method.lower() == 'get':
            qs = CrawlerCategory.objects.all().order_by("-created_at", "id")
            # 返回数组以匹配部分前端组件期待
            total, items, _, _ = paginate_queryset(request, qs)
            data = CrawlerCategorySerializer(items, many=True).data
            return drf_ok(data)
        # create
        payload = request.data or {}
        obj = CrawlerCategory.objects.create(
            name=payload.get('name', '') or payload.get('categoryName', ''),
            category_id=payload.get('category_id', '') or payload.get('categoryId', ''),
            site=payload.get('site', ''),
            category_type=payload.get('category_type', '') or payload.get('categoryType', ''),
            status=int(payload.get('status', 1)),
        )
        write_log(request, module='数据采集', action=f'新增类目：{obj.name}（ID={obj.id}）', result='success', elapsed_ms=0)
        return drf_ok(CrawlerCategorySerializer(obj).data, status=201)

    @action(detail=False, methods=["get"], url_path=r"(?P<id>[^/]+)/form")
    def form(self, request, id: str):
        try:
            obj = CrawlerCategory.objects.get(pk=id)
        except CrawlerCategory.DoesNotExist:
            return drf_error("未找到类目", status=404)
        return drf_ok(CrawlerCategorySerializer(obj).data)

    @action(detail=False, methods=["put", "delete"], url_path=r"(?P<ids>[^/]+)")
    def update_or_delete(self, request, ids: str):
        if request.method.lower() == 'put':
            first_id = ids.split(',')[0]
            try:
                obj = CrawlerCategory.objects.get(pk=first_id)
            except CrawlerCategory.DoesNotExist:
                return drf_error("未找到类目", status=404)
            p = request.data or {}
            if 'name' in p:
                obj.name = p.get('name') or obj.name
            if 'category_id' in p or 'categoryId' in p:
                obj.category_id = p.get('category_id') or p.get('categoryId') or obj.category_id
            if 'site' in p:
                obj.site = p.get('site') or obj.site
            if 'category_type' in p or 'categoryType' in p:
                obj.category_type = p.get('category_type') or p.get('categoryType') or obj.category_type
            if 'status' in p:
                try:
                    obj.status = int(p.get('status'))
                except Exception:
                    pass
            obj.save()
            write_log(request, module='数据采集', action=f'更新类目：{obj.name}（ID={obj.id}）', result='success', elapsed_ms=0)
            return drf_ok(CrawlerCategorySerializer(obj).data)
        # delete
        id_list = [i for i in ids.split(',') if i]
        CrawlerCategory.objects.filter(id__in=id_list).delete()
        write_log(request, module='数据采集', action=f'删除类目：{ids}', result='success', elapsed_ms=0)
        return drf_ok(status=204)

    @action(detail=True, methods=["get"], url_path="times", permission_classes=[IsAuthenticated])
    def times(self, request, id: str):
        """获取指定类目在 Seafile 资料库下的时间文件夹列表。

        流程：
        - 读取字典 `cloud_type` 中的配置，找到 Seafile `site`（base site）与目标 repo id（从字典项 value 中获取，匹配 `CrawlerCategory.site` 字段优先）
        - 使用当前登录用户的缓存 token（CloudAuthToken）调用 Seafile API:
          GET {base_site}/api2/repos/{repo_id}/dir/?p=/数据采集/{category_id}
        - 返回目录中符合时间格式的文件夹名列表（按字典序/时间倒序），并默认返回最新 3 条用于展示
        """
        try:
            try:
                cat = CrawlerCategory.objects.get(pk=id)
            except CrawlerCategory.DoesNotExist:
                return drf_error("未找到类目", status=404)

            # 解析 Seafile site 与 repo_id
            base_site, repo_id, err = _resolve_site_and_repo(cat.site)
            if err:
                return drf_error(err, status=400)

            # 获取当前用户缓存的 token
            try:
                from .utils.seafile import get_cached_token, invalidate_user_token
            except Exception:
                get_cached_token = None
                invalidate_user_token = None

            token = None
            if get_cached_token:
                try:
                    token = get_cached_token(request.user, base_site)
                except Exception:
                    token = None

            if not token:
                # 收集当前用户的 CloudAuthToken 概览（不包含 token 值），便于诊断缓存未命中的原因
                cache_info = {"entries": 0, "matched": False, "sites": []}
                try:
                    from .models import CloudAuthToken
                    rows = list(CloudAuthToken.objects.filter(user=request.user).values('site', 'expires_at'))
                    cache_info['entries'] = len(rows)
                    for r in rows:
                        s = (r.get('site') or '').rstrip('/')
                        exp = r.get('expires_at')
                        cache_info['sites'].append({"site": s, "expires_at": str(exp)})
                        if s == base_site.rstrip('/'):
                            cache_info['matched'] = True
                except Exception:
                    pass
                try:
                    write_log(request, module='Crawler', action=f'seafile cache miss for user={getattr(request.user, "id", None)} site={base_site}', result='fail', elapsed_ms=0)
                except Exception:
                    pass
                return drf_error("未找到缓存的 Seafile token，请提供 cloudPassword 刷新缓存", status=401, data={"needCloudPassword": True, "cacheInfo": cache_info})

            # 请求 Seafile 列出目录
            try:
                auth_header = {"Authorization": f"Token {token}", "Accept": "application/json, text/plain, */*"}
                repo_url = base_site.rstrip('/') + f"/api2/repos/{quote(repo_id)}/dir/"
                # 按新规则：目录路径使用类目的 site 字段（即类目站点），
                # 若未提供则回退到 category_id，以兼容旧数据。
                folder_name = (cat.site or str(cat.category_id or "")).strip()
                # 去掉首尾斜杠，保证路径拼接正确
                folder_name = folder_name.strip('/')
                params = {"p": f"/爬虫数据/{folder_name}/"}
                resp = requests.get(repo_url, headers=auth_header, params=params, timeout=10)
            except Exception as e:
                try:
                    write_log(request, module='Crawler', action=f'Seafile request failed: {e}', result='fail', elapsed_ms=0)
                except Exception:
                    pass
                return drf_error("请求 Seafile 失败", status=502, data={"msg": str(e), "exc": type(e).__name__})

            if resp.status_code in (401, 403):
                try:
                    if invalidate_user_token:
                        invalidate_user_token(request.user, base_site)
                except Exception:
                    pass
                return drf_error("Seafile 认证失败或 token 无效，请重新输入 cloud 密码", status=401, data={"needCloudPassword": True, "status": resp.status_code})

            if not (200 <= resp.status_code < 300):
                txt = getattr(resp, 'text', '')
                return drf_error(f"Seafile 返回错误: {resp.status_code}", status=502, data={"msg": txt})

            # 解析目录条目，筛选文件夹名（日期样式）
            try:
                jr = resp.json()
            except Exception:
                jr = None

            names = []
            if isinstance(jr, list):
                for it in jr:
                    # 支持不同返回结构
                    nm = None
                    if isinstance(it, dict):
                        nm = it.get('name') or it.get('path') or it.get('filename')
                        is_dir = bool(it.get('is_dir') or (it.get('type') == 'dir') or it.get('isdir') )
                    else:
                        nm = str(it)
                        is_dir = False
                    if nm and is_dir:
                        # 仅接受像 20251119 的日期型文件夹名（6-8 位数字）
                        if re.match(r"^\d{6,8}$", str(nm)):
                            names.append(str(nm))
            # 去重与排序（倒序，最新在前）
            uniq = sorted(list(set(names)), reverse=True)
            latest = uniq[:3]

            # 构造响应
            data = {"list": [{"index": i + 1, "name": n} for i, n in enumerate(latest)], "all": uniq}
            return drf_ok(data)
        except Exception as e:
            return drf_error("服务器内部错误", status=500, data={"msg": str(e)})

    @action(detail=False, methods=["get"], url_path="sites")
    def sites(self, request):
        """返回所有去重后的类目站点列表，用于前端下拉选择"""
        try:
            qs = CrawlerCategory.objects.all().order_by('site').values_list('site', flat=True).distinct()
            sites = [s for s in list(qs) if s]
            return drf_ok(sites)
        except Exception as e:
            return drf_error('获取站点列表失败', status=500, data={'msg': str(e)})

    @action(detail=True, methods=["get"], url_path="file/check", permission_classes=[IsAuthenticated])
    def file_check(self, request, id: str):
        """检查指定类目在某个时间点是否存在 xlsx 文件（不下载），返回 { exists: true } 或 404/false

        请求参数: time=<folder name>
        """
        try:
            t = request.query_params.get('time') or request.query_params.get('date')
            if not t:
                return drf_error("缺少 time 参数", status=400)
            try:
                cat = CrawlerCategory.objects.get(pk=id)
            except CrawlerCategory.DoesNotExist:
                return drf_error("未找到类目", status=404)

            base_site, repo_id, err = _resolve_site_and_repo(cat.site)
            if err:
                return drf_error(err, status=400)

            try:
                from .utils.seafile import get_cached_token
            except Exception:
                get_cached_token = None

            token = None
            if get_cached_token:
                try:
                    token = get_cached_token(request.user, base_site)
                except Exception:
                    token = None

            if not token:
                cache_info = {"entries": 0, "matched": False, "sites": [], "hasToken": False}
                try:
                    from .models import CloudAuthToken
                    rows = list(CloudAuthToken.objects.filter(user=request.user).values('site', 'expires_at', 'token'))
                    cache_info['entries'] = len(rows)
                    for r in rows:
                        s = (r.get('site') or '').rstrip('/')
                        exp = r.get('expires_at')
                        cache_info['sites'].append({"site": s, "expires_at": str(exp)})
                        # 是否存在非空 token（不将 token 回传给前端）
                        if r.get('token'):
                            cache_info['hasToken'] = True
                        if s == base_site.rstrip('/'):
                            cache_info['matched'] = True
                except Exception:
                    pass
                try:
                    # 额外写日志记录以便诊断（不要在响应中泄露 token）
                    write_log(request, module='Crawler', action=f'seafile cache miss for user={getattr(request.user, "id", None)} site={base_site} entries={cache_info.get("entries")} matched={cache_info.get("matched")} hasToken={cache_info.get("hasToken")}', result='fail', elapsed_ms=0)
                except Exception:
                    pass
                return drf_error("未找到缓存的 Seafile token，请提供 cloudPassword 刷新缓存", status=401, data={"needCloudPassword": True, "cacheInfo": cache_info})

            # 构建文件路径
            folder, file_name, p_raw, view_path_parts = _build_paths(cat, t)
            params = {"p": p_raw}
            try:
                auth_header = {"Authorization": f"Token {token}", "Accept": "application/json, text/plain, */*"}
                repo_url = base_site.rstrip('/') + f"/api2/repos/{quote(repo_id)}/file/"
                # 不自动跟随重定向，目的是读取 Seafile 返回的 Location header（若 Seafile 返回外部下载地址）
                r = requests.get(repo_url, headers=auth_header, params=params, stream=False, timeout=15, allow_redirects=False)
                # 若 Seafile 返回重定向，取 Location 作为最终下载外链
                if r.status_code in (301, 302, 303, 307, 308):
                    download_url = r.headers.get('Location')
                    try:
                        view_path = "/".join([quote(p) for p in ["爬虫数据", folder, t, file_name]])
                        view_url = base_site.rstrip('/') + f"/lib/{quote(repo_id)}/file/{view_path}"
                    except Exception:
                        view_url = None
                    return drf_ok({"exists": True, "viewUrl": view_url, "downloadUrl": download_url})

                # 若 200 且返回类型为文本（可能直接为一个 URL 或 JSON），尝试解析
                if r.status_code == 200:
                    ctype = (r.headers.get('Content-Type') or '').lower()
                    body = ''
                    try:
                        body = r.text or ''
                    except Exception:
                        body = ''
                    # 若 body 看起来是 URL，则直接返回；另外即便 Content-Type 为 JSON，也尝试用正则提取 URL（去掉可能的引号）
                    body_str = (body or '').strip()
                    # 去除外部可能的双引号或单引号包裹
                    if len(body_str) >= 2 and ((body_str[0] == '"' and body_str[-1] == '"') or (body_str[0] == "'" and body_str[-1] == "'")):
                        body_str = body_str[1:-1].strip()
                    if body_str.startswith('http://') or body_str.startswith('https://'):
                        download_url = body_str
                        try:
                            view_path = "/".join([quote(p) for p in ["爬虫数据", folder, t, file_name]])
                            view_url = base_site.rstrip('/') + f"/lib/{quote(repo_id)}/file/{view_path}"
                        except Exception:
                            view_url = None
                        return drf_ok({"exists": True, "viewUrl": view_url, "downloadUrl": download_url})

                    # 若返回 JSON，检查是否为 File not found 错误；但即便是 JSON，也尝试在原始文本中提取 seafhttp 链接
                    try:
                        if 'application/json' in ctype:
                            try:
                                jr = r.json()
                            except Exception:
                                jr = None
                            if isinstance(jr, dict) and (jr.get('error_msg') or jr.get('detail')):
                                msg = jr.get('error_msg') or jr.get('detail') or ''
                                if 'File not found' in msg or 'not found' in msg.lower():
                                    # 返回 200 并指示文件不存在，前端根据返回的 exists=false 处理
                                    return drf_ok({'exists': False, 'error_msg': msg})
                                return drf_error(f"Seafile 返回错误", status=502, data={'msg': msg})
                    except Exception:
                        pass

                    # 不论 Content-Type，尝试用正则在 body 中查找 seafhttp 外链
                    try:
                        bt = body or ''
                        m = re.search(r"https?://[\w\-\.\/:=%?&]+/(?:seafhttp|seaf)/[\w\-\.\/:=%?&]+", bt)
                        if m:
                            download_url = m.group(0).strip().strip('"\'')
                            try:
                                view_path = "/".join([quote(p) for p in ["爬虫数据", folder, t, file_name]])
                                view_url = base_site.rstrip('/') + f"/lib/{quote(repo_id)}/file/{view_path}"
                            except Exception:
                                view_url = None
                            return drf_ok({"exists": True, "viewUrl": view_url, "downloadUrl": download_url})
                    except Exception:
                        pass

                    # 其他情况：在回退到构造 API 下载链接前，主动探测该 API 是否会返回外链或重定向到外部地址。
                    try:
                        # 使用 allow_redirects=True 的普通 GET（不 stream），检查最终的 response.url 和 body 内容
                        probe = None
                        try:
                            probe = requests.get(repo_url, headers=auth_header, params=params, timeout=20, allow_redirects=True)
                        except Exception:
                            probe = None
                        if probe is not None:
                            try:
                                final_url = getattr(probe, 'url', '') or ''
                                if final_url and final_url.strip() and (final_url != repo_url) and (final_url.startswith('http://') or final_url.startswith('https://')):
                                    # 若最终 URL 包含 seafhttp，优先返回
                                    if '/seafhttp/' in final_url or '/seaf/' in final_url:
                                        download_url = final_url
                                        try:
                                            view_path = "/".join([quote(p) for p in ["爬虫数据", folder, t, file_name]])
                                            view_url = base_site.rstrip('/') + f"/lib/{quote(repo_id)}/file/{view_path}"
                                        except Exception:
                                            view_url = None
                                        return drf_ok({"exists": True, "viewUrl": view_url, "downloadUrl": download_url})
                                # 如果 body 文本包含 seafhttp 链接，也提取返回
                                try:
                                    body_text = probe.text or ''
                                except Exception:
                                    body_text = ''
                                if '/seafhttp/' in body_text or '/seaf/' in body_text:
                                    m = re.search(r"https?://[\w\-\.\/:=%?&]+/seafhttp/[\w\-\.\/:=%?&]+", body_text)
                                    if m:
                                        download_url = m.group(0)
                                        try:
                                            view_path = "/".join([quote(p) for p in ["爬虫数据", folder, t, file_name]])
                                            view_url = base_site.rstrip('/') + f"/lib/{quote(repo_id)}/file/{view_path}"
                                        except Exception:
                                            view_url = None
                                        return drf_ok({"exists": True, "viewUrl": view_url, "downloadUrl": download_url})
                            except Exception:
                                pass
                        # 若探测失败或未能获取外链，则回退到构造的 API 下载链接
                    except Exception:
                        pass
                    download_url = base_site.rstrip('/') + f"/api2/repos/{quote(repo_id)}/file/?p={quote(p_raw)}"
                    try:
                        view_path = "/".join([quote(p) for p in ["爬虫数据", folder, t, file_name]])
                        view_url = base_site.rstrip('/') + f"/lib/{quote(repo_id)}/file/{view_path}"
                    except Exception:
                        view_url = None
                    return drf_ok({"exists": True, "viewUrl": view_url, "downloadUrl": download_url})

                if r.status_code == 404:
                    # 当 Seafile 返回 404 时，统一以 200 返回并标记不存在，由前端决定如何展示
                    return drf_ok({"exists": False, "error_msg": "File not found"})
                if r.status_code in (401, 403):
                    # 若 Seafile 返回 JSON 指示 Invalid token，且本次请求携带 cloudPassword，则尝试用该密码刷新 token 并重试一次
                    tried_refresh = False
                    try:
                        ctype = (r.headers.get('Content-Type') or '').lower()
                        body_txt = ''
                        try:
                            body_txt = r.text or ''
                        except Exception:
                            body_txt = ''
                        invalid_token_flag = False
                        if 'application/json' in ctype:
                            try:
                                jr = r.json()
                                if isinstance(jr, dict) and (jr.get('detail') == 'Invalid token' or 'invalid token' in str(jr.get('detail', '')).lower()):
                                    invalid_token_flag = True
                            except Exception:
                                pass
                        # 若识别为 Invalid token 并且前端在本次请求中传入密码参数，则尝试刷新
                        if invalid_token_flag:
                            try:
                                req_password = request.query_params.get('cloudPassword') or request.query_params.get('password') or None
                            except Exception:
                                req_password = None
                            if req_password:
                                try:
                                    from .utils.seafile import get_or_fetch_user_token, cache_token_for_user
                                except Exception:
                                    get_or_fetch_user_token = None
                                    cache_token_for_user = None
                                if get_or_fetch_user_token:
                                    try:
                                        new_token, err = get_or_fetch_user_token(request.user, base_site, provided_password=req_password, request=request)
                                        if new_token:
                                            # 尝试缓存并重试请求一次
                                            try:
                                                if cache_token_for_user:
                                                    cache_token_for_user(request.user, base_site, new_token)
                                            except Exception:
                                                pass
                                            tried_refresh = True
                                            auth_header = {"Authorization": f"Token {new_token}", "Accept": "application/json, text/plain, */*"}
                                            try:
                                                r = requests.get(repo_url, headers=auth_header, params=params, stream=False, timeout=15, allow_redirects=False)
                                            except Exception:
                                                r = None
                                    except Exception:
                                        pass
                    except Exception:
                        pass
                    # 若已尝试刷新并且新的响应仍然 401/403，或未尝试刷新，则返回需要密码提示
                    if r is None or (getattr(r, 'status_code', None) in (401, 403)):
                        return drf_error("Seafile 认证失败", status=401, data={"needCloudPassword": True})
                txt = getattr(r, 'text', '')
                return drf_error(f"Seafile 返回错误: {r.status_code}", status=502, data={"msg": txt})
            except Exception as e:
                try:
                    write_log(request, module='Crawler', action=f'Seafile file_check request failed: {e}', result='fail', elapsed_ms=0)
                except Exception:
                    pass
                return drf_error("请求 Seafile 失败", status=502, data={"msg": str(e), "exc": type(e).__name__})
        except Exception as e:
            return drf_error("服务器内部错误", status=500, data={"msg": str(e)})

    @action(detail=True, methods=["get"], url_path="file", permission_classes=[IsAuthenticated])
    def file(self, request, id: str):
        """从 Seafile 下载并透传指定类目的 xlsx 文件内容给前端（stream）。

        请求参数: time=<folder name>
        """
        try:
            t = request.query_params.get('time') or request.query_params.get('date')
            if not t:
                return drf_error("缺少 time 参数", status=400)
            try:
                cat = CrawlerCategory.objects.get(pk=id)
            except CrawlerCategory.DoesNotExist:
                return drf_error("未找到类目", status=404)

            # 读取 site & repo_id
            site = None
            repo_id = None
            try:
                items = list(DictItem.objects.filter(dict_type__code__in=["cloud_type", "clooud_type"], status=True))
                if items:
                    for it in items:
                        label = (it.label or "").lower()
                        val = (it.value or "").strip()
                        if not site and ("site" in label or "站" in label or val.startswith("http")):
                            site = val
                    exact_labels = {"资料库id", "资料库 id", "资料库ID", "repo id", "repoid", "repository id"}
                    for it in items:
                        lab = (it.label or "").strip()
                        if lab in exact_labels:
                            repo_id = (it.value or "").strip()
                            break
                    if not repo_id and len(items) == 1:
                        repo_id = (items[0].value or "").strip()
            except Exception:
                items = []

            if not site or not repo_id:
                return drf_error("未在字典中配置 Seafile 站点或资料库 ID", status=400)

            base_site = str(site).strip()
            if not re.match(r"^https?://", base_site, re.I):
                base_site = "https://" + base_site

            try:
                from .utils.seafile import get_cached_token
            except Exception:
                get_cached_token = None

            token = None
            if get_cached_token:
                try:
                    token = get_cached_token(request.user, base_site)
                except Exception:
                    token = None

            if not token:
                return drf_error("未找到缓存的 Seafile token，请提供 cloudPassword 刷新缓存", status=401, data={"needCloudPassword": True})

            folder = str(cat.site or '').strip('/')
            file_name = f"{cat.category_id}_{cat.site}.xlsx"
            folder, file_name, p_raw, view_path_parts = _build_paths(cat, t)
            params = {"p": p_raw}
            try:
                auth_header = {"Authorization": f"Token {token}", "Accept": "application/json, application/octet-stream, text/plain, */*"}
                repo_url = base_site.rstrip('/') + f"/api2/repos/{quote(repo_id)}/file/"
                # 不自动跟随重定向，读取 Location 或 body 中的实际下载地址
                r = requests.get(repo_url, headers=auth_header, params=params, timeout=30, allow_redirects=False)
            except Exception as e:
                try:
                    write_log(request, module='Crawler', action=f'Seafile file request failed: {e}', result='fail', elapsed_ms=0)
                except Exception:
                    pass
                return drf_error("请求 Seafile 失败", status=502, data={"msg": str(e), "exc": type(e).__name__})

            if r.status_code in (301, 302, 303, 307, 308):
                download_url = r.headers.get('Location')
                download_url = download_url or (base_site.rstrip('/') + f"/api2/repos/{quote(repo_id)}/file/?p={quote(p_raw)}")
                try:
                    view_path = "/".join([quote(p) for p in view_path_parts])
                    view_url = base_site.rstrip('/') + f"/lib/{quote(repo_id)}/file/{view_path}"
                except Exception:
                    view_url = None
                return drf_ok({"exists": True, "viewUrl": view_url, "downloadUrl": download_url})
                if r.status_code == 200:
                    ctype = (r.headers.get('Content-Type') or '').lower()
                    body = ''
                    try:
                        body = r.text or ''
                    except Exception:
                        body = ''
                    # 如果 body 是直接的 URL（可能包含引号），做简单裁剪并返回
                    body_str = (body or '').strip()
                    if len(body_str) >= 2 and ((body_str[0] == '"' and body_str[-1] == '"') or (body_str[0] == "'" and body_str[-1] == "'")):
                        body_str = body_str[1:-1].strip()
                    if body_str.startswith('http://') or body_str.startswith('https://'):
                        download_url = body_str
                        try:
                            view_path = "/".join([quote(p) for p in view_path_parts])
                            view_url = base_site.rstrip('/') + f"/lib/{quote(repo_id)}/file/{view_path}"
                        except Exception:
                            view_url = None
                        return drf_ok({"exists": True, "viewUrl": view_url, "downloadUrl": download_url})

                    # 若返回 JSON 并包含 error_msg，则按错误返回（不展示）；否则继续尝试从文本中提取外链
                    try:
                        if 'application/json' in ctype:
                            try:
                                jr = r.json()
                            except Exception:
                                jr = None
                            if isinstance(jr, dict) and (jr.get('error_msg') or jr.get('detail')):
                                msg = jr.get('error_msg') or jr.get('detail') or ''
                                if 'File not found' in msg or 'not found' in msg.lower():
                                    return drf_error('File not found', status=404, data={'error_msg': msg})
                                return drf_error(f"Seafile 返回错误", status=502, data={'msg': msg})
                    except Exception:
                        pass

                    # 不论 Content-Type，正则尝试提取包含 /seafhttp/ 的外链
                    try:
                        bt = body or ''
                        m = re.search(r"https?://[\w\-\.\/:=%?&]+/(?:seafhttp|seaf)/[\w\-\.\/:=%?&]+", bt)
                        if m:
                            download_url = m.group(0).strip().strip('"\'')
                            try:
                                view_path = "/".join([quote(p) for p in view_path_parts])
                                view_url = base_site.rstrip('/') + f"/lib/{quote(repo_id)}/file/{view_path}"
                            except Exception:
                                view_url = None
                            return drf_ok({"exists": True, "viewUrl": view_url, "downloadUrl": download_url})
                    except Exception:
                        pass

                    # fallback: 构造 API 下载链接
                    download_url = base_site.rstrip('/') + f"/api2/repos/{quote(repo_id)}/file/?p={quote(p_raw)}"
                    try:
                        view_path = "/".join([quote(p) for p in view_path_parts])
                        view_url = base_site.rstrip('/') + f"/lib/{quote(repo_id)}/file/{view_path}"
                    except Exception:
                        view_url = None
                    return drf_ok({"exists": True, "viewUrl": view_url, "downloadUrl": download_url})

            if r.status_code == 404:
                return drf_error('File not found', status=404, data={'error_msg': 'File not found'})
            if r.status_code in (401, 403):
                # 支持检测返回 JSON 中的 Invalid token，若本次请求携带 cloudPassword 则尝试刷新 token 并重试一次
                tried_refresh = False
                try:
                    ctype = (r.headers.get('Content-Type') or '').lower()
                    body_txt = ''
                    try:
                        body_txt = r.text or ''
                    except Exception:
                        body_txt = ''
                    invalid_token_flag = False
                    if 'application/json' in ctype:
                        try:
                            jr = r.json()
                            if isinstance(jr, dict) and (jr.get('detail') == 'Invalid token' or 'invalid token' in str(jr.get('detail', '')).lower()):
                                invalid_token_flag = True
                        except Exception:
                            pass
                    if invalid_token_flag:
                        try:
                            req_password = request.query_params.get('cloudPassword') or request.query_params.get('password') or None
                        except Exception:
                            req_password = None
                        if req_password:
                            try:
                                from .utils.seafile import get_or_fetch_user_token, cache_token_for_user
                            except Exception:
                                get_or_fetch_user_token = None
                                cache_token_for_user = None
                            if get_or_fetch_user_token:
                                try:
                                    new_token, err = get_or_fetch_user_token(request.user, base_site, provided_password=req_password, request=request)
                                    if new_token:
                                        try:
                                            if cache_token_for_user:
                                                cache_token_for_user(request.user, base_site, new_token)
                                        except Exception:
                                            pass
                                        tried_refresh = True
                                        auth_header = {"Authorization": f"Token {new_token}", "Accept": "application/json, application/octet-stream, text/plain, */*"}
                                        try:
                                            r = requests.get(repo_url, headers=auth_header, params=params, timeout=30, allow_redirects=False)
                                        except Exception:
                                            r = None
                                except Exception:
                                    pass
                except Exception:
                    pass
                if r is None or (getattr(r, 'status_code', None) in (401, 403)):
                    return drf_error('Seafile 认证失败', status=401, data={'needCloudPassword': True})
            txt = getattr(r, 'text', '')
            return drf_error(f'Seafile 返回错误: {r.status_code}', status=502, data={'msg': txt})
        except Exception as e:
            return drf_error('服务器内部错误', status=500, data={'msg': str(e)})
