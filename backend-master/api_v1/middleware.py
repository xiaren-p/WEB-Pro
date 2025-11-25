"""请求日志中间件

记录 /api/v1/ 下的请求到 OperLog：
- module: 前两段路径或首段（如 users / roles）
- action: 方法名（view 对应的函数名或 HTTP method）
- operator: 用户名（匿名则空）
- ip: 请求来源 IP
- user_agent: UA
- elapsed_ms: 执行耗时毫秒

低风险实现：仅在响应成功或失败都写日志；不抛异常影响主流程。
后续可扩展：忽略静态文件、批量写入、异常栈等。
"""
from __future__ import annotations
import time
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpRequest, HttpResponse
from .models import OperLog


class OperLogMiddleware(MiddlewareMixin):
    def process_request(self, request: HttpRequest):
        request._oplog_start = time.time()
        return None

    def process_response(self, request: HttpRequest, response: HttpResponse):
        try:
            path = request.path
            if not path.startswith('/api/v1/'):
                return response
            # 基本路径拆解
            segs = [s for s in path[len('/api/v1/'):].split('/') if s]
            module = segs[0] if segs else 'root'
            action = request.method.lower()
            user = getattr(request, 'user', None)
            operator = user.username if user and getattr(user, 'is_authenticated', False) else ''
            ip = request.META.get('REMOTE_ADDR', '')
            ua = request.META.get('HTTP_USER_AGENT', '')[:255]
            elapsed_ms = int((time.time() - getattr(request, '_oplog_start', time.time())) * 1000)
            OperLog.objects.create(
                module=module,
                action=action,
                operator=operator,
                ip=ip,
                user_agent=ua,
                result='success' if 200 <= response.status_code < 400 else 'error',
                elapsed_ms=elapsed_ms,
            )
        except Exception:
            # 不影响主流程
            pass
        return response

    def process_exception(self, request: HttpRequest, exception: Exception):
        try:
            path = request.path
            if not path.startswith('/api/v1/'):
                return None
            segs = [s for s in path[len('/api/v1/'):].split('/') if s]
            module = segs[0] if segs else 'root'
            action = request.method.lower()
            user = getattr(request, 'user', None)
            operator = user.username if user and getattr(user, 'is_authenticated', False) else ''
            ip = request.META.get('REMOTE_ADDR', '')
            ua = request.META.get('HTTP_USER_AGENT', '')[:255]
            elapsed_ms = int((time.time() - getattr(request, '_oplog_start', time.time())) * 1000)
            OperLog.objects.create(
                module=module,
                action=action,
                operator=operator,
                ip=ip,
                user_agent=ua,
                result='error',
                elapsed_ms=elapsed_ms,
            )
        except Exception:
            pass
        return None
