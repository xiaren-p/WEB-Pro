from rest_framework.response import Response
from rest_framework.renderers import JSONRenderer
from rest_framework.views import exception_handler as drf_exception_handler
from rest_framework.exceptions import (
    APIException,
    NotAuthenticated,
    PermissionDenied,
    NotFound,
    ValidationError,
    AuthenticationFailed,
)

SUCCESS_CODE = "00000"
PARAM_ERROR_CODE = "B0001"
AUTH_ERROR_CODE = "A0201"  # 未登录
PERMISSION_DENIED_CODE = "A0301"  # 无权限
NOT_FOUND_CODE = "A0404"  # 资源不存在
SERVER_ERROR_CODE = "B0500"  # 服务器内部错误

def drf_ok(data=None, msg: str = "success", status: int = 200) -> Response:
    # 204 No Content 不应携带响应体，避免浏览器/代理层的 Content-Length 异常
    if status == 204:
        return Response(status=status)
    return Response({"code": SUCCESS_CODE, "data": data, "msg": msg}, status=status)


def drf_error(msg: str = "error", code: str = PARAM_ERROR_CODE, status: int = 400, data=None) -> Response:
    return Response({"code": code, "data": data, "msg": msg}, status=status)


class BizError(Exception):
    def __init__(self, msg: str, code: str = PARAM_ERROR_CODE, status: int = 400, data=None):
        super().__init__(msg)
        self.msg = msg
        self.code = code
        self.status = status
        self.data = data


def exception_to_response(exc: Exception) -> Response:
    if isinstance(exc, BizError):
        return drf_error(exc.msg, code=exc.code, status=exc.status, data=exc.data)
    # 未知异常
    return drf_error("服务器内部错误", code=SERVER_ERROR_CODE, status=500)


def custom_exception_handler(exc, context):
    """
    统一异常处理：
    - BizError -> 业务错误包裹
    - DRF 标准异常 -> 转换为统一包格式 {code,data,msg}
    - 其它异常 -> 500 统一错误
    """
    # BizError 优先
    if isinstance(exc, BizError):
        return exception_to_response(exc)

    # 让 DRF 先处理（包括校验错误等），拿到 Response 后再包裹
    response = drf_exception_handler(exc, context)
    if response is not None:
        status = response.status_code
        # 映射常见异常到统一 code
        if isinstance(exc, (NotAuthenticated, AuthenticationFailed)):
            code = AUTH_ERROR_CODE
            msg = str(getattr(exc, 'detail', '未登录'))
        elif isinstance(exc, PermissionDenied):
            code = PERMISSION_DENIED_CODE
            msg = str(getattr(exc, 'detail', '无权限'))
        elif isinstance(exc, NotFound):
            code = NOT_FOUND_CODE
            msg = str(getattr(exc, 'detail', '资源不存在'))
        elif isinstance(exc, ValidationError):
            code = PARAM_ERROR_CODE
            # ValidationError 可能是字典/列表，统一取字符串
            detail = getattr(exc, 'detail', None)
            msg = '参数错误'
            data = detail
            return drf_error(msg=msg, code=code, status=status, data=data)
        else:
            code = SERVER_ERROR_CODE
            msg = str(getattr(exc, 'detail', '服务器错误'))
        # 其它已被 DRF 识别的异常，统一包裹 message
        return drf_error(msg=msg, code=code, status=status, data=response.data)

    # 非 DRF 识别的异常 -> 统一 500
    return exception_to_response(exc)
