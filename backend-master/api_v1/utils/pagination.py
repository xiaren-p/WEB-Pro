"""统一分页工具

提供 paginate_queryset(request, queryset, default_page_size=10)
返回 (total, items, page_num, page_size)

读取参数：pageNum / pageSize
容错：非法数字回退默认

后续可扩展：动态最大 pageSize、排序字段统一处理、过滤器抽象。
"""
from typing import Tuple, Any
from django.db.models import QuerySet

def paginate_queryset(request, queryset: QuerySet, default_page_size: int = 10) -> Tuple[int, Any, int, int]:
    try:
        page_num = int(request.query_params.get('pageNum', 1))
    except Exception:
        page_num = 1
    try:
        page_size = int(request.query_params.get('pageSize', default_page_size))
    except Exception:
        page_size = default_page_size
    if page_num < 1:
        page_num = 1
    if page_size < 1:
        page_size = default_page_size
    total = queryset.count()
    start = (page_num - 1) * page_size
    end = start + page_size
    items = queryset[start:end]
    return total, items, page_num, page_size
