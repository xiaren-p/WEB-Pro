"""操作日志写入工具

提供一个简单的 write_log 方法，便于在视图中记录关键操作。
"""
from typing import Optional
from django.utils import timezone
from django.http import HttpRequest

from api_v1.models import OperLog


def get_client_ip(request: HttpRequest) -> str:
    try:
        # 优先 X-Forwarded-For (反向代理场景)，取第一个非空 IP
        xff = request.META.get('HTTP_X_FORWARDED_FOR')
        if xff:
            for ip in xff.split(','):
                ip = ip.strip()
                if ip:
                    return ip
        ip = request.META.get('REMOTE_ADDR') or ''
        return ip
    except Exception:
        return ''


def write_log(
    request: Optional[HttpRequest],
    module: str,
    action: str,
    *,
    result: str = 'success',
    elapsed_ms: int = 0,
):
    """写入一条 OperLog

    参数：
    - request: HttpRequest，可为 None
    - module: 模块名
    - action: 操作内容
    - result: 结果标识（success/fail/…）
    - elapsed_ms: 执行耗时（毫秒）
    """
    try:
        operator = ''
        ip = ''
        user_agent = ''
        if request is not None:
            user = getattr(request, 'user', None)
            if user is not None and getattr(user, 'is_authenticated', False):
                operator = getattr(user, 'username', '') or ''
            ip = get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
        OperLog.objects.create(
            module=module or '',
            action=action or '',
            operator=operator,
            ip=ip,
            user_agent=user_agent,
            result=result or 'success',
            elapsed_ms=int(elapsed_ms) if isinstance(elapsed_ms, (int, float)) else 0,
        )
    except Exception:
        # 保底：日志写入失败不影响业务流程
        pass
