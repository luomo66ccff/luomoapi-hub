import os
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates


router = APIRouter()
templates = Jinja2Templates(directory="app/web/templates")


def get_db_path() -> str:
    return os.getenv("DATABASE_PATH", "/app/data/luomoapi.db")


def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()}


def get_public_route_stats() -> dict[str, int]:
    db_path = get_db_path()

    if not Path(db_path).exists():
        return {
            "enabled_routes": 0,
            "disabled_routes": 0,
            "documented_routes": 0,
        }

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    try:
        documented = conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM public_gateway_routes
            WHERE public_docs = 1
            """
        ).fetchone()["c"]

        enabled = conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM public_gateway_routes
            WHERE public_docs = 1 AND enabled = 1
            """
        ).fetchone()["c"]
        disabled = conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM public_gateway_routes
            WHERE public_docs = 1 AND enabled = 0
            """
        ).fetchone()["c"]

        return {
            "enabled_routes": int(enabled or 0),
            "disabled_routes": int(disabled or 0),
            "documented_routes": int(documented or 0),
        }
    except Exception:
        return {
            "enabled_routes": 0,
            "disabled_routes": 0,
            "documented_routes": 0,
        }
    finally:
        conn.close()


def get_public_routes() -> list[dict[str, Any]]:
    db_path = get_db_path()

    if not Path(db_path).exists():
        return []

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    try:
        rows = conn.execute(
            """
            SELECT
                id,
                name,
                public_path,
                target_method,
                required_scope,
                enabled,
                public_docs,
                allow_anonymous
            FROM public_gateway_routes
            WHERE public_docs = 1
            ORDER BY enabled DESC, name ASC
            """
        ).fetchall()

        return [row_to_dict(row) for row in rows]
    except Exception:
        return []
    finally:
        conn.close()


@router.get("/api/public/stats")
def public_stats_api():
    return JSONResponse(get_public_route_stats())


@router.get("/api/public/routes")
def public_routes_api():
    return JSONResponse(
        {
            "routes": get_public_routes(),
            "stats": get_public_route_stats(),
        }
    )


@router.get("/security", response_class=PlainTextResponse)
def security_policy():
    return security_text()


@router.get("/.well-known/security.txt", response_class=PlainTextResponse)
def well_known_security_txt():
    return security_text()


def security_text() -> str:
    contact = os.getenv("SECURITY_CONTACT", "security@example.com").strip()
    canonical_base = os.getenv("APP_BASE_URL", "http://localhost:8790").rstrip("/")
    return "\n".join(
        [
            f"Contact: mailto:{contact}",
            "Preferred-Languages: zh, en",
            f"Canonical: {canonical_base}/.well-known/security.txt",
            f"Policy: {canonical_base}/security",
            "",
            "Scope: public portal, developer console, API key gateway, and account flows.",
            "Out of scope: denial-of-service testing, social engineering, credential stuffing, destructive testing, and attempts against unrelated services.",
            "Please do not include secrets, API keys, passwords, cookies, or private user data in reports.",
            "",
        ]
    )


@router.get("/")
def public_home(request: Request):
    stats = get_public_route_stats()
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            **stats,
        },
    )


@router.get("/docs")
def public_docs(request: Request):
    routes = get_public_routes()
    stats = get_public_route_stats()
    return templates.TemplateResponse(
        "docs.html",
        {
            "request": request,
            "routes": routes,
            **stats,
        },
    )
