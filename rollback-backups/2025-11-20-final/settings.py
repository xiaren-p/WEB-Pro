"""
Django 配置（backend_master）

要点：
- 开发环境下启用 CORS 方便前后端联调；
- 使用 DRF 作为 API 框架，解析 JSON/Form/Multipart；
- 统一响应与分页在视图层封装，保持 {code,data,msg} 与 {total,list}；
- 使用 django-environ 读取 .env 配置，便于不同环境切换。
"""

from pathlib import Path
import os
import environ

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# ---- Env settings ----
env = environ.Env(
	DEBUG=(bool, True),
	SECRET_KEY=(str, 'django-insecure-v9t&lx8patv5db$l)y#4jioqhrvzzl!cg6k4grcn2ow0%+jd^r'),
	ALLOWED_HOSTS=(list, ['127.0.0.1', 'localhost']),
	CORS_ALLOW_ALL_ORIGINS=(bool, True),
	CSRF_TRUSTED_ORIGINS=(list, ['http://localhost:3000', 'http://127.0.0.1:3000']),
	ACCESS_TOKEN_EXPIRE_SECONDS=(int, 3600),
	REFRESH_TOKEN_EXPIRE_SECONDS=(int, 3600 * 24 * 7),
	# 可选：对外可访问的后端基础 URL（例如 http://192.168.0.251:8000），用于在 API 中生成对外可访问的绝对文件 URL
	BACKEND_EXTERNAL_URL=(str, ''),
	# WebSocket 使用的 Redis 通道层地址（未配置则使用内存层，仅适合开发单进程）
	REDIS_URL=(str, ''),
	# 在线用户心跳过期秒数（超过该秒数未 ping 视为离线）
	ONLINE_STALE_SECONDS=(int, 180),
)

env_file = BASE_DIR / '.env'
if env_file.exists():
	environ.Env.read_env(env_file)


# Quick-start development settings - unsuitable for production
# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = env('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = env('DEBUG')

ALLOWED_HOSTS = env('ALLOWED_HOSTS')


# 应用定义

INSTALLED_APPS = [
	'django.contrib.admin',
	'django.contrib.auth',
	'django.contrib.contenttypes',
	'django.contrib.sessions',
	'django.contrib.messages',
	'django.contrib.staticfiles',
	'rest_framework',      # DRF
	'corsheaders',         # CORS（开发）
	'api_v1',              # 业务接口 v1
]

MIDDLEWARE = [
	'django.middleware.security.SecurityMiddleware',
	'django.contrib.sessions.middleware.SessionMiddleware',
	'corsheaders.middleware.CorsMiddleware',  # 必须置于 CommonMiddleware 之前
	'django.middleware.common.CommonMiddleware',
	'django.middleware.csrf.CsrfViewMiddleware',
	'django.contrib.auth.middleware.AuthenticationMiddleware',
	'django.contrib.messages.middleware.MessageMiddleware',
	'django.middleware.clickjacking.XFrameOptionsMiddleware',
	'api_v1.middleware.OperLogMiddleware',  # 记录请求日志（仅 /api/v1/*）
]

ROOT_URLCONF = 'backend_master.urls'

TEMPLATES = [
	{
		'BACKEND': 'django.template.backends.django.DjangoTemplates',
		'DIRS': [BASE_DIR / 'templates']
		,
		'APP_DIRS': True,
		'OPTIONS': {
			'context_processors': [
				'django.template.context_processors.request',
				'django.contrib.auth.context_processors.auth',
				'django.contrib.messages.context_processors.messages',
			],
		},
	},
]

WSGI_APPLICATION = 'backend_master.wsgi.application'
ASGI_APPLICATION = 'backend_master.asgi.application'


# 数据库（开发默认 SQLite，后续可切换至 MySQL/PostgreSQL）

DATABASES = {
	'default': {
		'ENGINE': 'django.db.backends.sqlite3',
		'NAME': BASE_DIR / 'db.sqlite3',
	}
}


# Password validation
# https://docs.djangoproject.com/en/5.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
	{
		'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
	},
	{
		'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
	},
	{
		'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
	},
	{
		'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
	},
]


# 国际化

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# 静态文件

STATIC_URL = 'static/'

# 媒体文件（文件上传）
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# 默认主键类型

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# 默认头像（用户未上传头像时使用）。可根据需要替换为 CDN/OSS 地址。
DEFAULT_AVATAR_URL = 'https://foruda.gitee.com/images/1723603502796844527/03cdca2a_716974.gif'

# 对外可访问的后端 URL（例如内部开发机对局域网可见的 IP）
BACKEND_EXTERNAL_URL = env('BACKEND_EXTERNAL_URL')
ONLINE_STALE_SECONDS = env('ONLINE_STALE_SECONDS')

# CORS（开发环境）
CORS_ALLOW_ALL_ORIGINS = env('CORS_ALLOW_ALL_ORIGINS')  # 生产建议改为 CORS_ALLOWED_ORIGINS 精确白名单
CORS_ALLOW_CREDENTIALS = True
# 允许的自定义请求头（包含 Authorization，便于携带令牌）
CORS_ALLOW_HEADERS = [
	'accept',
	'accept-encoding',
	'authorization',
	'content-type',
	'dnt',
	'origin',
	'user-agent',
	'x-csrftoken',
	'x-requested-with',
]
# 暴露的响应头（文件下载场景需要）
CORS_EXPOSE_HEADERS = [
	'Content-Disposition',
]

# 信任本地前端域名（CSRF）
CSRF_TRUSTED_ORIGINS = env('CSRF_TRUSTED_ORIGINS')

# DRF 设置（解析器）。分页/响应统一在视图内封装。
REST_FRAMEWORK = {
	'DEFAULT_PARSER_CLASSES': (
		'rest_framework.parsers.JSONParser',
		'rest_framework.parsers.FormParser',
		'rest_framework.parsers.MultiPartParser',
	),
	'DEFAULT_AUTHENTICATION_CLASSES': (
		'api_v1.auth.BearerTokenAuthentication',
		'rest_framework.authentication.SessionAuthentication',
	),
	'DEFAULT_PERMISSION_CLASSES': (
		'rest_framework.permissions.IsAuthenticated',
	),
	'EXCEPTION_HANDLER': 'api_v1.utils.responses.custom_exception_handler',
}

# 认证令牌有效期（秒）
ACCESS_TOKEN_EXPIRE_SECONDS = env('ACCESS_TOKEN_EXPIRE_SECONDS')
REFRESH_TOKEN_EXPIRE_SECONDS = env('REFRESH_TOKEN_EXPIRE_SECONDS')

# 文件管理模块已下线；如需恢复请参考历史提交

# Channels 已从项目中移除；保留 REDIS_URL 以备将来需要，但不再配置 CHANNEL_LAYERS
REDIS_URL = env('REDIS_URL')
