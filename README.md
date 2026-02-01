# Authentication Service API

![Tests](https://github.com/danisatree/AuthenticationAPI/actions/workflows/test.yml/badge.svg)
![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)

A standalone, reusable authentication microservice built with FastAPI, SQLAlchemy, and JWT Bearer tokens.

## Features
- **User Registration**: `POST /api/v1/auth/signup`
- **Login**: `POST /api/v1/auth/login` (Returns JWT Bearer Token)
- **Token Refresh**: `POST /api/v1/auth/refresh` (Sliding session)
- **Profile Management**: Get, update, and delete user profiles.
- **Password Management**: Change and reset passwords.
- **Database Agnostic**: Supports SQLite (default) and PostgreSQL.
- **Security**: Includes Rate Limiting, Clickjacking protection, XSS protection, and Trusted Host middleware.
- **Observability**: Structured JSON logging and Request ID tracking for easier debugging and monitoring.

## Getting Started

### Prerequisites
- Python 3.12+
- [Poetry](https://python-poetry.org/) (Dependency Manager)

### Local Setup

1.  **Install Dependencies**:
    ```bash
    poetry install
    ```

2.  **Environment Configuration**:
    Copy `.env.example` to `.env` and update secrets:
    ```bash
    cp .env.example .env
    ```

3.  **Run Locally**:
    ```bash
    poetry run uvicorn app.main:app --reload
    ```
    Access Swagger UI at [http://localhost:8000/docs](http://localhost:8000/docs).

### Docker Deployment

1.  **Build the Image**:
    ```bash
    docker build -t auth-service .
    ```

2.  **Run the Container**:
    ```bash
    docker run -d -p 8000:8000 --name auth-service --env-file .env auth-service
    ```
    Access at `http://localhost:8000`.

## Security Configuration

- **Trusted Host Middleware**: By default, `ALLOWED_HOSTS` is set to `["*"]` to allow easy local development. **For production, you must update this list in `app/main.py`** to include only your allowed domains (e.g., `["example.com", "*.example.com"]`) to prevent Host Header attacks.

## Verification

To verify that the application is running correctly and security headers are active:

```bash
curl -I http://localhost:8000/api/health
```

Expected output includes security headers and a unique Request ID:
```http
HTTP/1.1 200 OK
x-frame-options: DENY
x-content-type-options: nosniff
x-request-id: <unique-uuid>
...
```

## API Documentation

- **Swagger UI**: `/docs` - Interactive API documentation and testing.
- **ReDoc**: `/redoc` - Alternative API documentation.

## Integration Guide

To use this service in your other applications (Web/Mobile):

1.  **Login**: Send credentials to `/api/v1/auth/login`.
2.  **Store Token**: Save the `access_token` securely (e.g., `SecureStore` on iOS, `EncryptedSharedPreferences` on Android, `HttpOnly Cookie` on Web).
3.  **Authenticate Requests**: Add header `Authorization: Bearer <your_token>` to requests requiring auth.
4.  **Handle 401 Unauthorized**: If a request fails with 401, try traversing to the login screen or using the `/refresh` endpoint if the session is still valid.

## Future Improvements

Based on the current implementation, the following enhancements are recommended to make the service production-ready and secure.

### 1. Implement Verification & Security
- **Email Verification**: Implement SMTP integration to send verification codes/links upon signup. Ensure users verify their email before logging in.


### 2. Upgrade Token Management
- **True Refresh Tokens**: Switch to a dual-token system:
    - **Access Token**: Short-lived (e.g., 15-30 mins).
    - **Refresh Token**: Long-lived (e.g., 7-30 days), stored securely in the database.
- **Redis Integration**:
    - **Token Revocation (Logout)**: Implement a "Blocklist" pattern using Redis to invalidate tokens instantly upon logout.
    - **Rate Limiting**: Use Redis to protect `/login` and `/signup` endpoints from brute-force attacks.

### 3. Role-Based Access Control (RBAC)
- Create a reusable dependency (e.g., `RequiresRole("admin")`) to protect endpoints based on the `Role` model.
- Seed default permissions and roles automatically on startup.

### 4. Observability & Monitoring
- **Metrics**: Add an endpoint (`/metrics`) exposing Prometheus-compatible metrics (latency, error rates).

### 5. Testing & Quality
- **Integration Tests**: Add tests using a real database (Dockerized Postgres) in CI to catch SQL dialect issues.
- **Load Testing**: Use Locust or K6 to benchmark authentication throughput.
