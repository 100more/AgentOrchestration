"""FastAPI application server."""

import os
from typing import Dict

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from .routes import router
from .webhook_dispatch import router as webhook_dispatch_router
from .middleware import AuthMiddleware, RateLimitMiddleware, LoggingMiddleware


def create_app(config: Dict = None) -> FastAPI:
    app = FastAPI(
        title="Agent Orchestrator API",
        version="2.4.1",
        description="Enterprise Agent Orchestration Platform API",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=os.getenv("TRUSTED_HOSTS", "*").split(","),
    )

    app.add_middleware(AuthMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(LoggingMiddleware)

    app.include_router(router, prefix="/api/v2")
    app.include_router(webhook_dispatch_router, prefix="/api/v2")

    @app.get("/health")
    async def health():
        return {"status": "healthy", "version": "2.4.1"}

    return app

# 2019-02-28T12:25:15 update

# 2019-09-10T11:29:29 update

# 2019-10-16T19:37:18 update

# 2019-11-09T08:51:56 update

# 2020-02-18T12:49:10 update

# 2020-04-17T11:39:46 update

# 2020-05-05T10:08:24 update

# 2020-05-11T14:56:21 update

# 2020-06-25T10:25:49 update

# 2020-08-18T09:56:20 update

# 2020-08-20T10:47:20 update

# 2020-09-10T17:33:24 update

# 2020-12-07T09:49:03 update

# 2020-12-21T14:05:39 update

# 2021-04-30T20:39:58 update

# 2021-07-27T13:57:47 update

# 2021-09-24T09:56:16 update

# 2021-10-20T09:31:19 update

# 2021-11-10T10:56:47 update

# 2022-02-08T12:59:06 update

# 2022-03-23T08:05:32 update

# 2022-04-29T15:09:49 update

# 2022-06-14T15:32:24 update

# 2022-07-18T14:13:48 update

# 2022-07-28T20:03:35 update

# 2022-08-26T10:17:51 update

# 2022-09-14T13:27:36 update

# 2023-01-27T17:27:08 update

# 2023-02-11T16:55:53 update

# 2023-04-24T18:24:33 update

# 2023-05-26T20:23:21 update

# 2023-12-05T13:56:00 update

# 2024-03-21T18:50:34 update

# 2024-05-23T19:22:50 update

# 2024-06-18T13:08:30 update

# 2024-06-28T13:40:10 update

# 2024-07-16T12:50:53 update

# 2024-07-19T08:53:12 update

# 2024-09-02T08:10:22 update

# 2024-11-19T18:53:36 update

# 2024-11-21T09:14:13 update

# 2024-11-25T16:30:21 update

# 2025-01-28T08:09:12 update

# 2025-02-25T09:57:53 update

# 2025-03-04T11:32:38 update

# 2025-04-17T13:32:53 update

# 2025-05-02T09:57:01 update

# 2025-05-14T18:28:03 update

# 2025-05-31T15:29:18 update

# 2025-08-26T13:58:43 update

# 2025-09-02T09:46:39 update

# 2025-10-22T12:48:03 update

# 2025-11-10T12:00:15 update

# 2025-11-12T12:33:57 update

# 2026-02-05T10:55:44 update

# 2026-03-10T10:40:58 update

# 2026-04-28T08:38:14 update

# 2026-05-19T18:09:43 update
