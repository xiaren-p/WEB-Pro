"""验证码生成工具"""
import uuid, base64, io, random, string
from django.core.cache import cache

try:
    from PIL import Image, ImageDraw, ImageFont, ImageFilter
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False


def generate_captcha(width: int = 120, height: int = 40, length: int = 4, expire: int = 300):
    text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
    key = uuid.uuid4().hex
    cache.set(f"captcha:{key}", text, timeout=expire)
    if not PIL_AVAILABLE:
        transparent_png = base64.b64encode(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x0cIDAT\x08\x99c``\x00\x00\x00\x04\x00\x01\x0b\xe7\x02\x9d\x00\x00\x00\x00IEND\xaeB`\x82").decode()
        return key, f"data:image/png;base64,{transparent_png}", text
    image = Image.new('RGB', (width, height), (255, 255, 255))
    draw = ImageDraw.Draw(image)
    for _ in range(6):
        x1, y1 = random.randint(0, width), random.randint(0, height)
        x2, y2 = random.randint(0, width), random.randint(0, height)
        draw.line(((x1, y1), (x2, y2)), fill=(200, 200, 200), width=1)
    try:
        font = ImageFont.truetype("arial.ttf", 28)
    except Exception:
        font = ImageFont.load_default()
    w, h = draw.textbbox((0, 0), text, font=font)[2:]
    draw.text(((width - w) / 2, (height - h) / 2), text, font=font, fill=(50, 50, 50))
    image = image.filter(ImageFilter.SMOOTH)
    buffer = io.BytesIO()
    image.save(buffer, format='PNG')
    b64 = base64.b64encode(buffer.getvalue()).decode()
    return key, f"data:image/png;base64,{b64}", text


def validate_captcha(key: str, code: str) -> bool:
    real = (cache.get(f"captcha:{key}") or '').lower()
    if not real or real != (code or '').lower():
        return False
    cache.delete(f"captcha:{key}")
    return True
