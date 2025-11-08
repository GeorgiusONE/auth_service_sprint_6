# Auth Service

Сервис аутентификации для онлайн-кинотеатра. Простой микросервис на FastAPI с JWT токенами, ролями и историей входов.

## Что умеет

### Аутентификация
- Регистрация новых пользователей
- Вход с выдачей JWT токенов
- Обновление токенов через refresh token
- Выход из текущей сессии
- Выход сразу из всех сессий

### Пользователи
- Просмотр своего профиля
- История входов с пагинацией
- Смена пароля

### Роли и права
- Создание, редактирование, удаление ролей
- Назначение ролей пользователям
- Проверка прав доступа
- Superuser может всё

### Безопасность
- Пароли хешируются через bcrypt
- JWT токены с коротким временем жизни (15 минут)
- Refresh токены живут 30 дней
- Blacklist для отозванных токенов
- При logout_all инвалидируются все токены пользователя

## Технологии

**Backend:**
- FastAPI 0.104.1
- Python 3.11+
- Uvicorn (ASGI server)

**База данных:**
- PostgreSQL 15 (asyncpg драйвер)
- SQLAlchemy 2.0 (async ORM)
- Alembic (миграции)

**Кэш:**
- Redis 7 для токенов и кэширования

**Безопасность:**
- PyJWT для токенов
- passlib + bcrypt для паролей

**Тесты:**
- pytest + pytest-asyncio
- httpx для HTTP тестов

## Структура проекта

```
auth-service/
├── src/
│   ├── main.py              # Точка входа
│   ├── api/                 # HTTP endpoints
│   │   ├── dependencies.py  # Зависимости FastAPI
│   │   └── v1/
│   │       ├── auth.py      # Аутентификация
│   │       ├── users.py     # Пользователи
│   │       └── roles.py     # Роли
│   ├── core/
│   │   ├── config.py        # Настройки
│   │   ├── security.py      # JWT + bcrypt
│   │   └── exceptions.py    # Исключения
│   ├── db/
│   │   ├── postgres.py      # PostgreSQL
│   │   └── redis_db.py      # Redis
│   ├── models/
│   │   ├── entity.py        # SQLAlchemy модели
│   │   └── schemas.py       # Pydantic схемы
│   ├── services/            # Бизнес-логика
│   │   ├── auth.py
│   │   ├── user.py
│   │   └── role.py
│   ├── cli/
│   │   └── commands.py      # CLI команды
│   └── migrations/          # Alembic
├── tests/                   # Тесты (78 штук)
├── docker-compose.yml
├── Dockerfile
└── requirements.txt
```

## Быстрый старт

### Клонирование и настройка

```bash
git clone <repository_url>
cd auth-service

# Скопировать конфиг
cp .env.example .env

# Отредактировать .env (поменять пароли и ключи)
nano .env
```

### Запуск через Docker

```bash
# Запустить всё (PostgreSQL, Redis, Auth Service)
docker-compose up -d

# Посмотреть логи
docker-compose logs -f auth-service

# Применить миграции
docker-compose exec auth-service alembic upgrade head

# Создать суперпользователя
docker-compose exec auth-service python -m src.cli.commands create-superuser
```

### Проверка

```bash
# Health check
curl http://localhost:8000/health

# Документация
open http://localhost:8000/docs
```

## Конфигурация

Основные параметры в `.env`:

```env
# Приложение
DEBUG=False
SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=another-secret-key

# PostgreSQL
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=auth_db
POSTGRES_USER=auth_user
POSTGRES_PASSWORD=change-this-password

# Redis
REDIS_HOST=redis
REDIS_PORT=6379

# JWT
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=30

# CORS
CORS_ORIGINS=["http://localhost:3000"]
```

Важно поменять `SECRET_KEY` и `JWT_SECRET_KEY` на случайные значения:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

## API Endpoints

### Authentication
- `POST /api/v1/auth/signup` - регистрация
- `POST /api/v1/auth/login` - вход
- `POST /api/v1/auth/refresh` - обновить токен
- `POST /api/v1/auth/logout` - выход
- `POST /api/v1/auth/logout-all` - выход из всех сессий

### Users
- `GET /api/v1/users/me` - мой профиль
- `GET /api/v1/users/me/login-history` - история входов
- `PUT /api/v1/users/me/password` - сменить пароль

### Roles (требуют admin или superuser)
- `POST /api/v1/roles` - создать роль
- `GET /api/v1/roles` - список ролей
- `GET /api/v1/roles/{id}` - инфо о роли
- `PUT /api/v1/roles/{id}` - обновить роль
- `DELETE /api/v1/roles/{id}` - удалить роль
- `POST /api/v1/roles/{role_id}/users/{user_id}` - назначить роль
- `DELETE /api/v1/roles/{role_id}/users/{user_id}` - отобрать роль
- `GET /api/v1/roles/check?role=subscriber` - проверить права

### System
- `GET /health` - статус сервиса
- `GET /` - информация о сервисе

Полная документация: http://localhost:8000/docs

## Примеры использования

### Регистрация

```bash
curl -X POST http://localhost:8000/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "login": "john_doe",
    "password": "SecurePass123!",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

### Вход

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "login": "john_doe",
    "password": "SecurePass123!"
  }'
```

Ответ:
```json
{
  "access_token": "eyJhbGci...",
  "refresh_token": "eyJhbGci...",
  "token_type": "bearer"
}
```

### Использование токена

```bash
# Сохранить токен
export TOKEN="your_access_token"

# Запросы с авторизацией
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/users/me
```

### Обновление токена

```bash
curl -X POST http://localhost:8000/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "your_refresh_token"}'
```

### История входов

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/v1/users/me/login-history?page=1&size=20"
```

## CLI Команды

### Создать суперпользователя

```bash
python -m src.cli.commands create-superuser
```

Спросит логин, пароль, имя и фамилию.

### Создать роль

```bash
python -m src.cli.commands create-role subscriber "Базовая подписка"
python -m src.cli.commands create-role admin
```

### Назначить роль

```bash
python -m src.cli.commands assign-role john_doe subscriber
```

### Списки

```bash
# Все пользователи
python -m src.cli.commands list-users

# С ролями
python -m src.cli.commands list-users --with-roles

# Все роли
python -m src.cli.commands list-roles
```

Через Docker:

```bash
docker-compose exec auth-service python -m src.cli.commands create-superuser
```

## Тестирование

Установить зависимости:

```bash
pip install fakeredis aiosqlite
```

Запустить тесты:

```bash
# Все тесты (78 штук)
pytest tests/

# С подробным выводом
pytest tests/ -v

# С покрытием
pytest tests/ --cov=src --cov-report=html

# Конкретный файл
pytest tests/test_auth.py

# Конкретный тест
pytest tests/test_auth.py::TestLogin::test_login_success
```

Структура тестов:
- `test_auth.py` - 23 теста (signup, login, refresh, logout)
- `test_users.py` - 20 тестов (профиль, история, пароль)
- `test_roles.py` - 35 тестов (CRUD, назначение, проверка прав)

## База данных

### Таблицы

**users** - пользователи
- id (UUID)
- login (unique)
- password (bcrypt hash)
- first_name, last_name
- is_active, is_superuser
- created_at, updated_at

**roles** - роли
- id (UUID)
- name (unique)
- description
- created_at, updated_at

**user_roles** - связь many-to-many
- user_id → users
- role_id → roles
- assigned_at

**login_history** - история входов
- user_id → users
- user_agent, ip_address
- fingerprint
- login_at, success

### Миграции

```bash
# Применить все миграции
alembic upgrade head

# Откатить на одну назад
alembic downgrade -1

# Посмотреть текущую версию
alembic current

# История миграций
alembic history
```

## Redis

Что хранится:

```
# Refresh токены (TTL: 30 дней)
refresh:{user_id}:{jti} = refresh_token

# Blacklist access токенов (TTL: до конца жизни токена)
blacklist:{jti} = user_id

# Версия токенов для logout_all (без TTL)
token_version:{user_id} = version

# Кэш ролей (TTL: 5 минут)
user_roles:{user_id} = [role1, role2, ...]

# Кэш данных пользователя (TTL: 5 минут)
user:{user_id} = {user_data}
```

## Deployment

### Production настройки

В `.env` поменять:

```env
DEBUG=False
SECRET_KEY=сгенерировать-длинный-случайный-ключ
JWT_SECRET_KEY=другой-длинный-ключ
CORS_ORIGINS=["https://your-domain.com"]
LOG_LEVEL=WARNING
```

### С nginx

```nginx
server {
    listen 80;
    server_name api.your-domain.com;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### Бэкапы PostgreSQL

```bash
# Ручной бэкап
docker-compose exec postgres pg_dump -U auth_user auth_db > backup.sql

# Автоматический (добавить в crontab)
0 2 * * * docker-compose exec -T postgres pg_dump -U auth_user auth_db | gzip > /backups/auth_$(date +\%Y\%m\%d).sql.gz
```

## Troubleshooting

### PostgreSQL не подключается

```bash
# Проверить статус
docker-compose ps postgres

# Посмотреть логи
docker-compose logs postgres

# Перезапустить
docker-compose restart postgres
```

### Redis не отвечает

```bash
# Проверить
docker-compose exec redis redis-cli ping

# Перезапустить
docker-compose restart redis
```

### Миграции не применяются

```bash
# Посмотреть текущую версию
docker-compose exec auth-service alembic current

# Применить вручную
docker-compose exec auth-service alembic upgrade head

# Откатить и применить заново
docker-compose exec auth-service alembic downgrade -1
docker-compose exec auth-service alembic upgrade head
```

### JWT токен невалиден

Возможные причины:
- Истёк срок (access token живёт 15 минут)
- Токен в blacklist (после logout)
- Версия не совпадает (после logout_all)
- Неправильный SECRET_KEY в .env

Решение - используй refresh token для получения нового access token.

### CORS ошибки

Добавь свой домен в `.env`:

```env
CORS_ORIGINS=["http://localhost:3000","https://your-domain.com"]
```

### Медленные запросы

Проверь:
- Индексы в БД (должны быть на login, user_id, role_id)
- Connection pool (можно увеличить в `db/postgres.py`)
- Redis работает (должен кэшировать роли)

## Мониторинг

### Health Check

```bash
curl http://localhost:8000/health
```

Ответ покажет статус PostgreSQL и Redis:

```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z",
  "version": "1.0.0",
  "dependencies": {
    "postgres": "connected",
    "redis": "connected"
  }
}
```

### Логи

```bash
# Все логи
docker-compose logs -f auth-service

# Последние 100 строк
docker-compose logs --tail=100 auth-service

# С временными метками
docker-compose logs -t auth-service
```

## Разработка

### Локальный запуск (без Docker)

```bash
# Установить зависимости
pip install -r requirements.txt

# Запустить PostgreSQL и Redis отдельно
# или через docker-compose up postgres redis

# Применить миграции
alembic upgrade head

# Запустить сервер
python -m src.main

# Или через uvicorn
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
```