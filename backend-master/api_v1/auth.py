"""
自定义 Bearer Token 认证（基于 AuthToken 模型）
"""
from typing import Tuple, Optional
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.models import User
from .models import AuthToken


class BearerTokenAuthentication(BaseAuthentication):
    keyword = b"Bearer"

    def authenticate(self, request) -> Optional[Tuple[User, AuthToken]]:
        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != self.keyword.lower():
            return None
        if len(auth) == 1:
            raise AuthenticationFailed("无效的认证头")
        if len(auth) > 2:
            raise AuthenticationFailed("无效的认证头")
        token = auth[1].decode()
        try:
            at = AuthToken.objects.select_related('user').get(access_token=token, revoked=False)
        except AuthToken.DoesNotExist:
            raise AuthenticationFailed("无效或已过期的令牌")
        if not at.is_access_valid():
            raise AuthenticationFailed("令牌已过期")
        return at.user, at
