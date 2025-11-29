from pathlib import Path
import os
from corsheaders.defaults import default_headers


CORS_ALLOW_HEADERS = list(default_headers) + [
    'access-control-allow-origin',
    'authorization',
    'content-type',
]


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-e-ar=#hq&(q0ujnwofc!%8#in(2z1osso65+(8i+&elo=cn4$k'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Application definition

INSTALLED_APPS = [
    'corsheaders',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',  # Required by django-allauth

    'rest_framework',
    'rest_framework.authtoken',

    'dj_rest_auth',
    'dj_rest_auth.registration',
    'django_filters',

    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    
    'django_countries',
    'channels',
    'aryuapp',   # Your app
    'live_quiz',
]

ASGI_APPLICATION = "Aryu.asgi.application"

# CHANNEL_LAYERS = {
#     "default": {
#         "BACKEND": "channels_redis.core.RedisChannelLayer",
#         "CONFIG": {
#             "hosts": [("127.0.0.1", 6379)],
#         },
#     },
# }

# CHANNEL_LAYERS = {
#     "default": {
#         "BACKEND": "channels_redis.core.RedisChannelLayer",
#         "CONFIG": {
#             "hosts": [{
#                 "address": ("69.62.78.109", 6379),
#                 "username": "aryuuser",
#                 "password": "Xc77D3f6",
#             }],
#         },
#     },
# }

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [
                "redis://aryuuser:Xc77D3f6@69.62.78.109:6379/0",
            ],
        },
    },
}

GZIP_MIN_LENGTH = 1024

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',  
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.gzip.GZipMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'aryuapp.middleware.AutoLogoutMiddleware',
    'aryuapp.middleware.DBCleanupMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'allauth.account.middleware.AccountMiddleware',
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'aryuapp.auth.CustomJWTAuthentication',
    ],
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend'
    ],
    'EXCEPTION_HANDLER': 'aryuapp.exceptions.custom_exception_handler',
}

# CORS_ALLOW_ALL_ORIGINS = True

CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:8000",
    "https://portal.aryuacademy.com",
]

CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:8000",
    "https://portal.aryuacademy.com",
    
]

ALLOWED_HOSTS = [
    "http://localhost:3000",
    "http://127.0.0.1:8000",
    "https://portal.aryuacademy.com",
    "127.0.0.1",
]  # Allow all hosts for development; change in production

RAZORPAY_KEY_ID = "rzp_test_RWUNL3DPw8Kmwk"
RAZORPAY_KEY_SECRET = "EhBVN3O6o1BMc2sQANsXXlzI"

CORS_ALLOW_CREDENTIALS = True

CORS_ALLOW_HEADERS = list(default_headers) + [
    'X-CSRFToken',
]
CORS_EXPOSE_HEADERS = ['Content-Type', 'X-CSRFToken']

CORS_ALLOW_METHODS = (
    "DELETE",
    "GET",
    "OPTIONS",
    "PATCH",
    "POST",
    "PUT",
)

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.hostinger.com"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = "info@aryuacademy.com"
EMAIL_HOST_PASSWORD = "SgSVEp?ev5|"
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER


SITE_ID = 1

SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"

SESSION_COOKIE_AGE = 1800  # 30 minutes in seconds
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

GOOGLE_CLIENT_ID = "1004056077681-qfeuc4edcpob49o1gk4168a3ap7lrnqs.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
GOOGLE_REDIRECT_URI = "http://127.0.0.1:8000/api/oauth2callback/"


ACCOUNT_LOGIN_METHODS = {'email'}
ACCOUNT_SIGNUP_FIELDS = ['email*', 'password1*', 'password2*']
ACCOUNT_EMAIL_VERIFICATION = 'mandatory'
ACCOUNT_CONFIRM_EMAIL_ON_GET = True

ROOT_URLCONF = 'Aryu.urls'

AUTH_USER_MODEL = 'aryuapp.User'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': ['templates'],
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

SECURE_SSL_REDIRECT = False

TWILIO_SID = "AC5ec75a85985e84acbe9bfa7a240d6386"
TWILIO_AUTH_TOKEN = "44fbdfc9f0960b464c20a193b797c7f7"
TWILIO_PHONE_NUMBER = "+15075854260"


MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

MEDIA_BASE_URL = "https://aylms.aryuprojects.com/api"

# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': 'academy_management',  
#         'USER': 'postgres',
#         'PASSWORD':'w9S1Es8',
#         'HOST': '69.62.78.109',   
#         'PORT': '5432',  
#         'AUTOCOMMIT': True,
#         'CONN_MAX_AGE': 60,
#     },
# }


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'academy_management_staging',
        'USER': 'academy_user',
        'PASSWORD':'c2lC47v',
        'HOST': '69.62.78.109',
        'PORT': '5432',
        'AUTOCOMMIT': True,
        'CONN_MAX_AGE': 60,
        'OPTIONS': {
            'options': '-c search_path=livequiz,public'
        }
    },
}

# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': 'academy_management',  
#         'USER': 'postgres',
#         'PASSWORD':'akzworld',
#         'HOST': 'localhost',
#         'PORT': '5432',  
#         'AUTOCOMMIT': True,
#         'OPTIONS': {
#             'options': '-c search_path=livequiz,public'
#         }
#     }
# }

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


# Internationalization
# https://docs.djangoproject.com/en/5.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Kolkata'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.2/howto/static-files/

BASE_DIR = Path(__file__).resolve().parent.parent

STATIC_URL = "/static/"
STATIC_ROOT = os.path.join(BASE_DIR, "static")

STATIC_URL = 'aryuapp/static/'
STATICFILES_DIRS = [
    BASE_DIR / "aryuapp/static",
]

MEDIA_URL = "/media/"
MEDIA_ROOT = os.path.join(BASE_DIR, "media")

# Default primary key field type
# https://docs.djangoproject.com/en/5.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

ROOT_URLCONF = 'Aryu.urls'

AUTH_USER_MODEL = 'aryuapp.User'

WSGI_APPLICATION = 'Aryu.wsgi.application'

USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')