"""FastAPI application factory for the LogLens Web UI and dashboard."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from loglens.llm import LLMProvider, MockLLMProvider, TriageOrchestrator, get_provider
from loglens.redact import Redactor
from loglens.store import DEFAULT_DB_PATH, StorageManager

MODULE_DIR = Path(__file__).resolve().parent
STATIC_DIR = MODULE_DIR / "static"
TEMPLATES_DIR = MODULE_DIR / "templates"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware applying strict Content-Security-Policy and security headers."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response


def create_app(
    db_path: Path | str | None = None,
    auth_token: str | None = None,
    llm_provider: LLMProvider | None = None,
    provider_name: str = "mock",
    model: str | None = None,
) -> FastAPI:
    """Create and configure the FastAPI web application for LogLens."""
    app = FastAPI(
        title="LogLens Web UI",
        description="Local-first AI-assisted security log triage dashboard",
        version="1.0.0",
    )

    # Security headers
    app.add_middleware(SecurityHeadersMiddleware)

    # Mount static assets
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Jinja2 template rendering
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    # Storage manager
    actual_db_path = db_path or os.environ.get("LOGLENS_DB_PATH") or DEFAULT_DB_PATH
    storage = StorageManager(actual_db_path)

    # LLM provider configuration for on-demand explain
    provider: LLMProvider
    if llm_provider is not None:
        provider = llm_provider
    elif provider_name == "mock":
        from loglens.models import LLMAssessment

        default_assessment = LLMAssessment(
            summary="Automated triage assessment from AI reasoning engine.",
            attack_type="security_anomaly",
            severity="high",
            confidence=0.95,
            evidence=["Suspicious cluster signature detected"],
            recommended_actions=["Review source IP access permissions"],
            false_positive_likelihood="low",
        )
        provider = MockLLMProvider(default_response=default_assessment)
    else:
        provider = get_provider(provider_name, model=model)

    orchestrator = TriageOrchestrator(provider=provider, redactor=Redactor(level="standard"))

    # Auth dependency
    def verify_token(request: Request) -> None:
        if not auth_token:
            return
        auth_header = request.headers.get("Authorization")
        query_token = request.query_params.get("token")
        provided_token = ""
        if auth_header and auth_header.startswith("Bearer "):
            provided_token = auth_header[7:].strip()
        elif query_token:
            provided_token = query_token.strip()

        if provided_token != auth_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    @app.get("/health")
    def health_check() -> dict[str, str]:
        """Health check endpoint."""
        return {"status": "ok", "version": "0.1.0"}

    @app.get("/", response_class=HTMLResponse, dependencies=[Depends(verify_token)])
    def dashboard(request: Request) -> HTMLResponse:
        """Render the main security triage operations dashboard."""
        stats = storage.get_global_stats()
        timeline = storage.get_timeline_stats(days=7)
        runs = storage.list_runs(limit=25)
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "stats": stats,
                "timeline": timeline,
                "runs": runs,
            },
        )

    @app.get("/runs/{run_id}", response_class=HTMLResponse, dependencies=[Depends(verify_token)])
    def run_detail(request: Request, run_id: str) -> HTMLResponse:
        """Render detailed view for a single triage run."""
        report = storage.get_run(run_id)
        if report is None:
            raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")

        return templates.TemplateResponse(
            request=request,
            name="run_detail.html",
            context={
                "run_id": run_id,
                "report": report,
            },
        )

    @app.post(
        "/runs/{run_id}/findings/{finding_id}/explain",
        response_class=HTMLResponse,
        dependencies=[Depends(verify_token)],
    )
    def explain_finding_on_demand(
        request: Request,
        run_id: str,
        finding_id: str,
    ) -> HTMLResponse:
        """HTMX endpoint to trigger on-demand LLM triage for an individual finding."""
        report = storage.get_run(run_id)
        if report is None:
            raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")

        target_finding = next((f for f in report.findings if f.id == finding_id), None)
        if target_finding is None:
            raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")

        # If already assessed, return card immediately
        if target_finding.llm is None:
            # Locate clusters linked to this finding
            matched_clusters = [c for c in report.clusters if c.id in target_finding.cluster_ids]
            if not matched_clusters:
                matched_clusters = report.clusters[:2]

            # Execute triage via orchestrator
            triaged_findings, _ = orchestrator.triage(matched_clusters, [target_finding])
            if triaged_findings and triaged_findings[0].llm:
                new_assessment = triaged_findings[0].llm
                target_finding.llm = new_assessment
                storage.update_finding_assessment(run_id, finding_id, new_assessment)

        return templates.TemplateResponse(
            request=request,
            name="partials/finding_card.html",
            context={
                "run_id": run_id,
                "finding": target_finding,
            },
        )

    @app.get("/api/stats", dependencies=[Depends(verify_token)])
    def api_stats() -> dict[str, Any]:
        """Return global telemetry and severity distribution stats."""
        return storage.get_global_stats()

    @app.get("/api/runs", dependencies=[Depends(verify_token)])
    def api_list_runs(limit: int = 50) -> list[dict[str, Any]]:
        """List historical runs in JSON format."""
        return storage.list_runs(limit=limit)

    @app.get("/api/runs/{run_id}", dependencies=[Depends(verify_token)])
    def api_get_run(run_id: str) -> dict[str, Any]:
        """Fetch complete run report in JSON format."""
        report = storage.get_run(run_id)
        if report is None:
            raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
        return report.model_dump(mode="json")

    return app
