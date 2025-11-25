import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.exceptions import DenyConnection
from django.utils import timezone
from urllib.parse import parse_qs
from typing import ClassVar, Dict, Set
from .models import AuthToken
from django.conf import settings

# 简单在线统计（仅适合单进程开发环境；多进程需使用共享存储或 Redis 计数）
class OnlineCountConsumer(AsyncWebsocketConsumer):
    online_count: ClassVar[int] = 0
    online_users: ClassVar[Set[int]] = set()  # user.id 集合
    last_broadcast_count: ClassVar[int] = -1
    last_seen: ClassVar[Dict[int, float]] = {}  # user.id -> timestamp
    STALE_SECONDS: ClassVar[int] = getattr(settings, 'ONLINE_STALE_SECONDS', 180)  # 动态可配置

    async def connect(self):
        raw_qs = self.scope.get('query_string', b'').decode()

        # 解析查询参数 token
        qs = parse_qs(raw_qs)
        token = qs.get('token', [None])[0]
        if not token:
            raise DenyConnection("missing token")
        # 校验访问令牌有效性
        try:
            at = AuthToken.objects.select_related('user').get(access_token=token, revoked=False)
            if not at.is_access_valid():
                raise DenyConnection("token expired")
            # 将用户放入 scope 以便后续扩展（权限、分发等）
            self.scope['user'] = at.user
        except AuthToken.DoesNotExist:
            raise DenyConnection("invalid token")

        await self.accept()
        uid = at.user.id
        type(self).online_users.add(uid)
        type(self).last_seen[uid] = timezone.now().timestamp()
        type(self).online_count = len(type(self).online_users)
        await self.channel_layer.group_add('online_count', self.channel_name)
        await self.broadcast_if_changed(force=True)

    async def disconnect(self, code):
        user = self.scope.get('user')
        if user:
            uid = user.id
            type(self).online_users.discard(uid)
            type(self).last_seen.pop(uid, None)
        type(self).online_count = len(type(self).online_users)
        await self.channel_layer.group_discard('online_count', self.channel_name)
        await self.broadcast_if_changed(force=True)

    async def receive(self, text_data=None, bytes_data=None):
        # 客户端主动请求最新人数：发送 {"action": "ping"}
        if text_data:
            try:
                data = json.loads(text_data)
                action = data.get('action')
                if action == 'ping':
                    user = self.scope.get('user')
                    if user:
                        type(self).last_seen[user.id] = timezone.now().timestamp()
                    # 心跳时也做一次陈旧清理
                    await self.prune_stale()
                    await self.send_count(single=True)
            except Exception:
                # 忽略接收处理时的异常，避免关闭连接
                pass

    async def build_payload(self):
        # 精简后的负载：仅包含在线数量与时间戳
        return {
            'count': type(self).online_count,
            'timestamp': timezone.now().isoformat(),
        }

    async def send_count(self, single: bool = False):
        payload = await self.build_payload()
        if single:
            await self.send(json.dumps(payload))
        else:
            await self.channel_layer.group_send(
                'online_count',
                {
                    'type': 'online_count.event',
                    'payload': payload,
                }
            )

    async def broadcast_if_changed(self, force: bool = False):
        if force or type(self).online_count != type(self).last_broadcast_count:
            type(self).last_broadcast_count = type(self).online_count
            await self.send_count(single=False)

    async def prune_stale(self):
        now_ts = timezone.now().timestamp()
        stale = [uid for uid, ts in type(self).last_seen.items() if now_ts - ts > type(self).STALE_SECONDS]
        if stale:
            for uid in stale:
                type(self).online_users.discard(uid)
                type(self).last_seen.pop(uid, None)
            type(self).online_count = len(type(self).online_users)
            await self.broadcast_if_changed(force=True)

    async def online_count_event(self, event):
        await self.send(json.dumps(event['payload']))

class EchoConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()

    async def disconnect(self, code):
        pass

    async def receive(self, text_data=None, bytes_data=None):
        if text_data:
            await self.send(text_data)
        elif bytes_data:
            await self.send(bytes_data)
