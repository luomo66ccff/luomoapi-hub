from contextlib import closing
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from app.ai_catalog import snapshot
from app.auth import optional_user
from app.db import connect
from app.web.templating import templates


router = APIRouter()
EMPTY_STATS = {"enabled_routes": 0, "disabled_routes": 0, "documented_routes": 0}


def get_public_route_stats() -> dict[str, int]:
    try:
        with closing(connect()) as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS documented, COALESCE(SUM(enabled = 1), 0) AS enabled FROM public_gateway_routes WHERE public_docs = 1"
            ).fetchone()
    except Exception:
        return dict(EMPTY_STATS)
    documented, enabled = int(row["documented"] or 0), int(row["enabled"] or 0)
    return {"enabled_routes": enabled, "disabled_routes": documented - enabled, "documented_routes": documented}


def get_public_routes() -> list[dict[str, Any]]:
    try:
        with closing(connect()) as conn:
            rows = conn.execute(
                """
                SELECT id, name, public_path, target_method, required_scope, enabled, public_docs, allow_anonymous
                FROM public_gateway_routes
                WHERE public_docs = 1
                ORDER BY enabled DESC, name ASC
                """
            ).fetchall()
    except Exception:
        return []
    return [dict(row) for row in rows]


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
    return "\n".join(
        [
            "Contact: mailto:security@luomo.moe",
            "Contact: mailto:luomo0712@qq.com",
            "Preferred-Languages: zh, en",
            "Canonical: https://api.luomo.moe/.well-known/security.txt",
            "Policy: https://api.luomo.moe/security",
            "",
            "Scope: api.luomo.moe public portal, developer console, API key gateway, and LuomoAPI Hub account flows.",
            "Out of scope: denial-of-service testing, social engineering, credential stuffing, destructive testing, and attempts against SSH, firewall, Cloudflare records outside api.luomo.moe, or unrelated Luomo services.",
            "Please do not include secrets, API keys, passwords, cookies, or private user data in reports.",
            "",
        ]
    )


@router.get("/")
async def public_home(request: Request, user=Depends(optional_user)):
    return templates.TemplateResponse(request, "index.html", {"user": user, "catalog": await snapshot(), "routes": get_public_routes(), **get_public_route_stats()})


@router.get("/docs")
def public_docs(request: Request, user=Depends(optional_user)):
    return templates.TemplateResponse(request, "docs.html", {"user": user, "routes": get_public_routes(), **get_public_route_stats()})
