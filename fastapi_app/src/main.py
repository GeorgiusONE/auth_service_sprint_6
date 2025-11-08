"""
FastAPI приложение для сервиса аутентификации и авторизации.

Основные возможности:
- Регистрация и аутентификация пользователей
- JWT токены (access + refresh)
- Система ролей и управление правами доступа
- История входов в аккаунт
- Выход из всех сессий
"""

import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from src.api.v1 import auth, users, roles
from src.core.config import settings
from src.core.exceptions import AuthServiceException
from src.db.postgres import init_db, close_db, async_session_maker
from src.db.redis_db import init_redis, close_redis, redis_client
from src.models.schemas import HealthCheckResponse, DependencyStatus

# Настройка логирования
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Управление жизненным циклом приложения.
    
    Startup:
    - Инициализация PostgreSQL
    - Инициализация Redis
    
    Shutdown:
    - Закрытие соединений PostgreSQL
    - Закрытие соединений Redis
    """
    # Startup
    logger.info("Starting up Auth Service...")
    
    try:
        # Инициализация PostgreSQL
        await init_db()
        logger.info("PostgreSQL connection initialized")
        
        # Инициализация Redis
        await init_redis()
        logger.info("Redis connection initialized")
        
        logger.info(f"Auth Service started successfully on {settings.server_host}:{settings.server_port}")
        logger.info(f"Debug mode: {settings.debug}")
        logger.info(f"API documentation available at http://{settings.server_host}:{settings.server_port}/docs")
    except Exception as e:
        logger.error(f"Failed to start Auth Service: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down Auth Service...")
    
    try:
        # Закрытие PostgreSQL
        await close_db()
        logger.info("PostgreSQL connection closed")
        
        # Закрытие Redis
        await close_redis()
        logger.info("Redis connection closed")
        
        logger.info("Auth Service shut down successfully")
    except Exception as e:
        logger.error(f"Error during shutdown: {e}")


# Создание FastAPI приложения
app = FastAPI(
    title="Auth Service API",
    description="""
Сервис аутентификации и авторизации для онлайн-кинотеатра.

## Основные возможности:
- Регистрация и аутентификация пользователей
- JWT токены (access + refresh)
- Система ролей и управление правами доступа
- История входов в аккаунт
- Выход из всех сессий

## Безопасность:
- Пароли хешируются с использованием bcrypt
- JWT токены с коротким временем жизни (15 мин для access)
- Refresh токены хранятся в Redis
- Blacklist для недействительных токенов
    """,
    version="1.0.0",
    contact={
        "name": "Auth Service Team",
        "email": "support@cinema.com",
    },
    openapi_tags=[
        {
            "name": "Authentication",
            "description": "Операции аутентификации пользователей",
        },
        {
            "name": "Users",
            "description": "Операции с данными пользователей",
        },
        {
            "name": "Roles",
            "description": "Управление ролями и правами доступа",
        },
        {
            "name": "System",
            "description": "Системные endpoints",
        },
    ],
    lifespan=lifespan,
    debug=settings.debug,
)


# Настройка CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
logger.info(f"CORS configured with origins: {settings.cors_origins}")


# Custom Exception Handlers
@app.exception_handler(AuthServiceException)
async def auth_service_exception_handler(
    request: Request,
    exc: AuthServiceException
) -> JSONResponse:
    """
    Обработчик кастомных исключений сервиса аутентификации.
    
    Конвертирует AuthServiceException в HTTP response с правильным
    статус-кодом и структурой согласно ErrorResponse схеме.
    """
    logger.warning(
        f"Auth service exception: {exc.error_code} - {exc.detail}",
        extra={
            "error_code": exc.error_code,
            "status_code": exc.status_code,
            "path": request.url.path,
            "method": request.method,
        }
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.to_dict(),
    )


@app.exception_handler(Exception)
async def general_exception_handler(
    request: Request,
    exc: Exception
) -> JSONResponse:
    """
    Обработчик всех остальных неожиданных исключений.
    
    Логирует полную информацию об ошибке и возвращает
    generic error response клиенту.
    """
    logger.error(
        f"Unhandled exception: {str(exc)}",
        exc_info=True,
        extra={
            "path": request.url.path,
            "method": request.method,
        }
    )
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error" if not settings.debug else str(exc),
            "error_code": "INTERNAL_SERVER_ERROR",
            "timestamp": datetime.utcnow().isoformat() + "Z",
        },
    )


# Health Check Endpoint
@app.get(
    "/health",
    response_model=HealthCheckResponse,
    tags=["System"],
    summary="Health Check",
    description="Проверка состояния сервиса и его зависимостей",
)
async def health_check() -> HealthCheckResponse:
    """
    Проверка здоровья сервиса.
    
    Проверяет:
    - Доступность PostgreSQL
    - Доступность Redis
    
    Returns:
        HealthCheckResponse: Статус сервиса и его зависимостей
    """
    # Проверка PostgreSQL
    postgres_status = "disconnected"
    try:
        async with async_session_maker() as session:
            await session.execute(text("SELECT 1"))
            postgres_status = "connected"
    except Exception as e:
        logger.error(f"PostgreSQL health check failed: {e}")
    
    # Проверка Redis
    redis_status = "disconnected"
    try:
        await redis_client.ping()
        redis_status = "connected"
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
    
    # Определение общего статуса
    is_healthy = postgres_status == "connected" and redis_status == "connected"
    overall_status = "healthy" if is_healthy else "unhealthy"
    
    # Логирование
    if not is_healthy:
        logger.warning(
            f"Health check failed - Status: {overall_status}, "
            f"PostgreSQL: {postgres_status}, Redis: {redis_status}"
        )
    
    response = HealthCheckResponse(
        status=overall_status,
        timestamp=datetime.utcnow(),
        version="1.0.0",
        dependencies=DependencyStatus(
            postgres=postgres_status,
            redis=redis_status,
        ),
    )
    
    # Возврат 503 если сервис нездоров
    status_code = status.HTTP_200_OK if is_healthy else status.HTTP_503_SERVICE_UNAVAILABLE
    
    return JSONResponse(
        status_code=status_code,
        content=response.model_dump(mode='json'),
    )


# Подключение роутеров
app.include_router(
    auth.router,
    prefix="/api/v1/auth",
    tags=["Authentication"],
)
logger.info("Auth router registered at /api/v1/auth")

app.include_router(
    users.router,
    prefix="/api/v1/users",
    tags=["Users"],
)
logger.info("Users router registered at /api/v1/users")

app.include_router(
    roles.router,
    prefix="/api/v1/roles",
    tags=["Roles"],
)
logger.info("Roles router registered at /api/v1/roles")


# Root endpoint
@app.get(
    "/",
    include_in_schema=False,
)
async def root() -> dict[str, Any]:
    """
    Корневой endpoint.
    
    Возвращает базовую информацию о сервисе и ссылки на документацию.
    """
    return {
        "service": "Auth Service API",
        "version": "1.0.0",
        "status": "running",
        "documentation": {
            "swagger": "/docs",
            "redoc": "/redoc",
            "openapi": "/openapi.json",
        },
        "endpoints": {
            "health": "/health",
            "auth": "/api/v1/auth",
            "users": "/api/v1/users",
            "roles": "/api/v1/roles",
        },
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "src.main:app",
        host=settings.server_host,
        port=settings.server_port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )
