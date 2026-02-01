import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler

from app.api.v1 import api_v1_router
from app.database import init_db
from app.logger import logger
from app.limiter import limiter


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Register rate limit exceeded handler
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore

    # initialize database
    await init_db()
    logger.info("Database initialized")
    yield
    logger.info("Application shutting down")


app = FastAPI(
    title="Authentication Service API",
    version="1.0.0",
    description="Reusable Authentication Microservice",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Security: Trusted Host Middleware
# Prevents Host Header attacks. In production, list allowed hosts (e.g., ["example.com", "*.example.com"])
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"],  # Helper: Restrict this in production!
)


# Security: Additional Headers Middleware (Clickjacking, XSS, etc.)
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Helper: In production this should be restricted
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Observability: Request ID Middleware
@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request_id = str(uuid.uuid4())
    # Flatten the UUID to a hex string for cleaner logs if desired, but standard uuid is fine.

    # Inject into request state so endpoints can access it if needed
    request.state.request_id = request_id

    # Add to logger context (if using a context-aware logger, standard logging needs extra setup)
    # For now, we'll manually log it or rely on the fact it's in the response header for correlation

    response = await call_next(request)

    # Expose in response headers
    response.headers["X-Request-ID"] = request_id
    return response


# Include API v1 router
app.include_router(api_v1_router, prefix="/api")


@app.get("/health")
async def health_check():
    """
    Health check endpoint.
    """
    from sqlalchemy import text
    from app.database import engine

    health_status = {"status": "healthy", "service": "Authentication API", "version": "1.0.0", "database": "unknown"}

    # Check database connection
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        health_status["database"] = "connected"
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        health_status["database"] = "disconnected"
        health_status["status"] = "unhealthy"

    return health_status
