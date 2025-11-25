import sqlite3
from datetime import datetime
import os

db_path = r"c:/Users/PC/Desktop/WEB 项目/backend-master/db.sqlite3"
if not os.path.exists(db_path):
    print('DB not found:', db_path)
    exit(1)

con = sqlite3.connect(db_path)
cur = con.cursor()
try:
    cur.execute("SELECT id, user_id, site, token, expires_at FROM api_v1_cloudauthtoken")
    rows = cur.fetchall()
    if not rows:
        print('No CloudAuthToken rows')
    else:
        print('CloudAuthToken rows:')
        for r in rows:
            id, user_id, site, token, expires_at = r
            print('id:', id, 'user_id:', user_id)
            print('site:', site)
            print('token:', token[:6] + '...' if token else '')
            print('expires_at (raw):', expires_at)
            try:
                # sqlite stores datetimes as text, try to parse
                if expires_at:
                    # handle possible formats
                    for fmt in ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S'):
                        try:
                            dt = datetime.strptime(expires_at, fmt)
                            print('expires_at (parsed):', dt, 'now:', datetime.utcnow())
                            break
                        except Exception:
                            continue
            except Exception:
                pass
            print('---')
except Exception as e:
    print('query failed:', e)
finally:
    cur.close()
    con.close()
