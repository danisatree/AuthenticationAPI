# Changelog

All notable changes to this project will be documented in this file.

## [0.3.0] - 2026-01-29

### Added
- **Security**:
    - Rate Limiting support using `slowapi`.
    - Protected sensitive endpoints (`/signup`, `/login`, `/refresh`, `/password/reset`) from brute-force attacks.

## [0.2.0] - 2026-01-29

### Added
- **Security**:
    - `TrustedHostMiddleware` to prevent Host Header attacks.
    - Security headers: `X-Frame-Options` (Clickjacking protection), `X-Content-Type-Options`, and `X-XSS-Protection`.
- **Observability**:
    - `X-Request-ID` middleware for request tracking.
    - Structured JSON logging for production environments.

## [0.1.0] - 2026-01-21

### Added
- Initial release of the Authentication API.
- User signup (`/auth/signup`) and login (`/auth/login`) endpoints.
- JWT-based authentication with Bearer tokens.
- Protected user profile endpoints (`/users/me`).
- Password change and reset functionality.
- Docker support for containerized deployment.
- SQLite support by default, with PostgreSQL configuration available.
