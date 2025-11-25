"""Request logging middleware (backup)"""
from __future__ import annotations
import time
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpRequest, HttpResponse
from .models import OperLog


class ApiCsrfExemptMiddleware(MiddlewareMixin):
    """临时中间件备份（之前添加，用于 CSRF 免检）。"""
    def process_request(self, request: HttpRequest):
        try:
            path = getattr(request, 'path', '') or ''
            if path.startswith('/api/v1/'):
                setattr(request, '_dont_enforce_csrf_checks', True)
        except Exception:
            pass
        return None


class OperLogMiddleware(MiddlewareMixin):
    def process_request(self, request: HttpRequest):
        request._oplog_start = time.time()
        return None

    def process_response(self, request: HttpRequest, response: HttpResponse):
        try:
            path = request.path
            if not path.startswith('/api/v1/'):
                return response
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
