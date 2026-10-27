import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./vulntracker.db")
_secret_key = os.getenv("SECRET_KEY")
APP_ENV = os.getenv("APP_ENV", "development").lower()
if APP_ENV == "production" and not _secret_key:
    raise RuntimeError("SECRET_KEY must be supplied from the deployment secret manager")
# Development fallback only; production startup refuses to use it.
SECRET_KEY = _secret_key or "development-only-change-me-before-deploying"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
NOTIFY_SERVICE_URL = os.getenv("NOTIFY_SERVICE_URL", "http://localhost:3001")
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
]
