from django.utils import timezone
from django.conf import settings
from ..models import CloudAuthToken
from ..utils.oplog import write_log
import requests
import re
import os
import datetime
from django.utils import timezone as dj_timezone


def _normalize_site(site: str):
    base_site = str(site).strip()
    if not re.match(r"^https?://", base_site, re.I):
        base_site = "https://" + base_site
    auth_url = base_site.rstrip('/')
    if not re.search(r"api2/auth-token", auth_url, re.I):
        auth_url = auth_url + "/api2/auth-token/"
    return base_site, auth_url


def get_cached_token(user, site):
    try:
        base_site, _ = _normalize_site(site)
        # 使用不含末尾斜杠的 site key 做匹配，兼容历史存储差异（有/无末尾斜杠）
        site_key = base_site.rstrip('/')
        # 先尝试精准匹配 site 字段（多种写法兼容）
        objs = CloudAuthToken.objects.filter(user=user)
        now = dj_timezone.now()
        for obj in objs:
            try:
                if (obj.site or '').rstrip('/') != site_key:
                    continue
                if not (obj and obj.token and obj.expires_at):
                    continue
                exp = obj.expires_at
                try:
                    # Make expires_at timezone-aware using default timezone if naive
                    if dj_timezone.is_naive(exp):
                        exp = dj_timezone.make_aware(exp, dj_timezone.get_default_timezone())
                    # Compare in current timezone-aware context
                    if exp > now:
                        try:
                            # useful diagnostic log on hit
                            write_log(None, module='Auth', action=f'get_cached_token hit user={getattr(user, "id", None)} site={site_key} expires_at={exp} now={now}', result='success', elapsed_ms=0)
                        except Exception:
                            pass
                        return obj.token
                except Exception:
                    # Fallback: try direct comparison if above fails
                    try:
                        if obj.expires_at > now:
                            try:
                                write_log(None, module='Auth', action=f'get_cached_token hit (fallback) user={getattr(user, "id", None)} site={site_key} expires_at={obj.expires_at} now={now}', result='success', elapsed_ms=0)
                            except Exception:
                                pass
                            return obj.token
                    except Exception:
                        pass
            except Exception:
                continue
    except Exception:
        pass
    return None


def fetch_token_by_credentials(site, username, password, timeout=8):
    try:
        base_site, auth_url = _normalize_site(site)
        resp = requests.post(auth_url, json={"username": username, "password": password}, timeout=timeout)
        if 200 <= resp.status_code < 300:
            try:
                token = resp.json().get('token')
            except Exception:
                token = None
            if token:
                return token, None
            return None, 'no token in response'
        return None, f'seafile status {resp.status_code}'
    except Exception as e:
        return None, f'request error: {e}'


def cache_token_for_user(user, site, token):
    try:
        base_site, _ = _normalize_site(site)
        # 规范化存储为不含末尾斜杠的形式，避免以后匹配问题
        site_key = base_site.rstrip('/')
        ttl = int(getattr(settings, 'CLOUD_TOKEN_EXPIRE_SECONDS', 3600))
        expires = timezone.now() + timezone.timedelta(seconds=ttl)
        # Model `CloudAuthToken.user` is OneToOneField, so matching by (user, site)
        # can fail when attempting to create a second row for the same user.
        # Use user as the lookup key and store site in defaults to be compatible
        # with the existing OneToOne constraint.
        try:
            CloudAuthToken.objects.update_or_create(user=user, defaults={'site': site_key, 'token': token, 'expires_at': expires})
        except Exception:
            # Fallback: try to update existing record if any, else attempt create
            try:
                obj = CloudAuthToken.objects.filter(user=user).first()
                if obj:
                    obj.site = site_key
                    obj.token = token
                    obj.expires_at = expires
                    obj.save()
                else:
                    CloudAuthToken.objects.create(user=user, site=site_key, token=token, expires_at=expires)
            except Exception as e:
                try:
                    write_log(None, module='Auth', action=f'cache_token_for_user failed user={getattr(user, "id", None)} site={site_key} err={e}', result='fail', elapsed_ms=0)
                except Exception:
                    pass
                return False
        try:
            write_log(None, module='Auth', action=f'cache_token_for_user user={getattr(user, "id", None)} site={site_key} expires_at={expires}', result='success', elapsed_ms=0)
        except Exception:
            pass
        return True
    except Exception:
        return False


def invalidate_user_token(user, site=None):
    try:
        if site:
            base_site, _ = _normalize_site(site)
            site_key = base_site.rstrip('/')
            CloudAuthToken.objects.filter(user=user, site=site_key).delete()
        else:
            CloudAuthToken.objects.filter(user=user).delete()
    except Exception:
        pass


def get_or_fetch_user_token(user, site, provided_password=None, request=None):
    """
    返回 (token, error_dict_or_None).
    如果返回 token 为 None，则 error_dict 可包含友好提示给前端。
    """
    try:
        token = get_cached_token(user, site)
        if token:
            if request:
                try:
                    write_log(request, module='Auth', action=f'cache hit for seafile token (user={user.username})', result='success', elapsed_ms=0)
                except Exception:
                    pass
            return token, None
        # cache miss
        if request:
            try:
                write_log(request, module='Auth', action=f'cache miss for seafile token (user={user.username})', result='success', elapsed_ms=0)
            except Exception:
                pass
        if not provided_password:
            return None, {"success": False, "msg": "未提供当前用户密码，需提供以完成 Seafile 同步"}
        # 尝试使用提供的密码向 Seafile 获取 token（不在此处自动缓存，调用方决定是否缓存）
        token, err = fetch_token_by_credentials(site, user.username, provided_password)
        if token:
            # 不在此处缓存，留给调用方决定是否持久化到 CloudAuthToken
            if request:
                try:
                    write_log(request, module='Auth', action=f'fetched seafile token for user {user.username} (no-cache)', result='success', elapsed_ms=0)
                except Exception:
                    pass
            return token, None
        else:
            return None, {"success": False, "msg": err or "未能获取 Seafile token"}
    except Exception as e:
        return None, {"success": False, "msg": f"内部错误: {e}"}


def sync_profile_name(site, token, name):
    try:
        base_site, _ = _normalize_site(site)
        put_url = base_site.rstrip('/') + '/api/v2.1/user/'
        headers = {"Authorization": f"Token {token}", "Accept": "application/json"}
        r = requests.put(put_url, data={"name": name or ""}, headers=headers, timeout=10)
        return r
    except Exception as e:
        return None


def sync_avatar(site, token, fileobj, filename, content_type, timeout=20):
    try:
        base_site, _ = _normalize_site(site)
        avatar_url = base_site.rstrip('/') + '/api/v2.1/user-avatar/'
        files = {'avatar': (filename, fileobj, content_type)}
        headers = {"Authorization": f"Token {token}"}
        r = requests.post(avatar_url, files=files, headers=headers, timeout=timeout)
        return r
    except Exception:
        return None
