"""文件管理模块已下线：占位工具，所有上传请求返回 410。"""
from .responses import drf_error


def save_uploaded(file_obj, user=None):  # pragma: no cover
    return None, drf_error("文件管理已禁用", status=410)
