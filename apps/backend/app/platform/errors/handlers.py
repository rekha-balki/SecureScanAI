from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.platform.errors.error_response import ErrorResponse
from app.platform.errors.exceptions import (
    ConflictException,
    ForbiddenException,
    ResourceNotFoundException,
    UnauthorizedException,
    ValidationException,
)
from app.platform import get_logger

logger = get_logger(__name__)


def register_exception_handlers(app: FastAPI):

    @app.exception_handler(ResourceNotFoundException)
    async def not_found_handler(request: Request, exc: ResourceNotFoundException):
        logger.warning(str(exc))

        return JSONResponse(
            status_code=404,
            content=ErrorResponse(
                status=404,
                error="Not Found",
                message=str(exc),
                path=request.url.path,
            ).to_dict(),
        )

    @app.exception_handler(ValidationException)
    async def validation_handler(request: Request, exc: ValidationException):
        logger.warning(str(exc))

        return JSONResponse(
            status_code=400,
            content=ErrorResponse(
                status=400,
                error="Validation Error",
                message=str(exc),
                path=request.url.path,
            ).to_dict(),
        )

    @app.exception_handler(UnauthorizedException)
    async def unauthorized_handler(request: Request, exc: UnauthorizedException):
        logger.warning(str(exc))

        return JSONResponse(
            status_code=401,
            content=ErrorResponse(
                status=401,
                error="Unauthorized",
                message=str(exc),
                path=request.url.path,
            ).to_dict(),
        )

    @app.exception_handler(ForbiddenException)
    async def forbidden_handler(request: Request, exc: ForbiddenException):
        logger.warning(str(exc))

        return JSONResponse(
            status_code=403,
            content=ErrorResponse(
                status=403,
                error="Forbidden",
                message=str(exc),
                path=request.url.path,
            ).to_dict(),
        )

    @app.exception_handler(ConflictException)
    async def conflict_handler(request: Request, exc: ConflictException):
        logger.warning(str(exc))

        return JSONResponse(
            status_code=409,
            content=ErrorResponse(
                status=409,
                error="Conflict",
                message=str(exc),
                path=request.url.path,
            ).to_dict(),
        )

    @app.exception_handler(Exception)
    async def global_handler(request: Request, exc: Exception):
        logger.exception("Unhandled exception")

        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                status=500,
                error="Internal Server Error",
                message="Unexpected server error.",
                path=request.url.path,
            ).to_dict(),
        )