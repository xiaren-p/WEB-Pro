Standalone WebSocket service (ws + Redis)

This small service subscribes to a Redis channel (default `online_count`) and broadcasts messages to connected WebSocket clients.

Quick start (local):

1. Install dependencies

```powershell
cd ws-node
npm install
```

2. Create `.env` from `.env.example` and adjust values if needed

3. Start Redis (local) or point `REDIS_URL` to your Redis instance. Quick Docker Redis:

```powershell
docker run -p 6379:6379 -d redis:7
```

4. Start the service

```powershell
npm start
```

5. Test from browser console:

```javascript
const ws = new WebSocket('ws://127.0.0.1:9000/ws?token=YOUR_ACCESS_TOKEN');
ws.onmessage = ev => console.log('msg', ev.data);
```

Django publishing example (Python):

```python
import redis, json
from django.conf import settings

def publish_online_count(count):
    r = redis.Redis.from_url(settings.REDIS_URL)
    payload = json.dumps({ 'count': count, 'timestamp': datetime.utcnow().isoformat() })
    r.publish('online_count', payload)
```

Security:
# ws-node removed

This directory previously contained a standalone WebSocket microservice used during experimentation.
It has been neutralized as part of the rollback. Delete this directory from disk to remove it permanently.
