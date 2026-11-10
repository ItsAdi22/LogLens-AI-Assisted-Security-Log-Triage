"""FastAPI application factory for the LogLens Web UI and dashboard."""

from __future__ import annotations

import html
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from loglens.actions.exporter import generate_action_export
from loglens.cluster import DrainClusterer, extract_classified_errors
from loglens.ingest import group_multiline_logs
from loglens.llm import LLMProvider, MockLLMProvider, TriageOrchestrator, get_provider
from loglens.models import Event, Finding, LLMAssessment, Report, ReportMetadata
from loglens.notify import DiscordNotifier, TelegramNotifier, WebhookNotifier
from loglens.parsers import registry
from loglens.redact import Redactor
from loglens.rules import RuleEngine, get_builtin_rules
from loglens.store import DEFAULT_DB_PATH, StorageManager

MODULE_DIR = Path(__file__).resolve().parent
STATIC_DIR = MODULE_DIR / "static"
TEMPLATES_DIR = MODULE_DIR / "templates"

logger = logging.getLogger(__name__)


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


def resolve_notifier(channel: str, settings: dict[str, str]) -> Any:
    """Resolve and configure a notification backend using stored settings or env vars."""
    norm = channel.strip().lower()
    if norm == "telegram":
        token = settings.get("telegram_bot_token") or os.environ.get("TELEGRAM_BOT_TOKEN", "")
        chat = settings.get("telegram_chat_id") or os.environ.get("TELEGRAM_CHAT_ID", "")
        return TelegramNotifier(bot_token=token, chat_id=chat, min_severity="info")
    if norm == "discord":
        url = settings.get("discord_webhook_url") or os.environ.get("DISCORD_WEBHOOK_URL", "")
        return DiscordNotifier(webhook_url=url, min_severity="info")
    if norm == "webhook":
        url = settings.get("generic_webhook_url") or os.environ.get("LOGLENS_WEBHOOK_URL", "")
        sec = settings.get("generic_webhook_secret") or os.environ.get("LOGLENS_WEBHOOK_SECRET", "")
        return WebhookNotifier(webhook_url=url, secret=sec, min_severity="info")
    raise HTTPException(status_code=400, detail=f"Unsupported notification channel: '{channel}'")


def create_test_finding() -> Finding:
    """Create a synthetic finding payload for testing notification delivery."""
    return Finding(
        id="test-alert-001",
        cluster_ids=["c-test"],
        rule_ids=["UI-NOTIFICATION-TEST"],
        rule_severity="medium",
        llm=LLMAssessment(
            summary="Verification alert dispatched from LogLens Web UI settings panel.",
            attack_type="integration_test",
            severity="medium",
            confidence=1.0,
            evidence=["Manual notification test triggered via Web UI settings panel"],
            recommended_actions=["Verification confirmed. No further action needed."],
            false_positive_likelihood="low",
        ),
    )


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
        return {"status": "ok", "version": "1.0.0"}

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

    @app.get("/analyze", response_class=HTMLResponse, dependencies=[Depends(verify_token)])
    def analyze_page(request: Request) -> HTMLResponse:
        """Render the self-service log analysis and ingestion interface."""
        return templates.TemplateResponse(
            request=request,
            name="analyze.html",
            context={},
        )

    @app.post("/analyze", dependencies=[Depends(verify_token)])
    async def analyze_submit(
        file: UploadFile | None = File(None),
        log_text: str | None = Form(None),
        format: str = Form("auto"),
        provider: str = Form("mock"),
        enable_llm: bool = Form(False),
        notify_on_complete: bool = Form(False),
    ) -> RedirectResponse:
        """Process an uploaded log file or pasted raw log text, running triage and saving the run."""
        text_content = ""
        source_name = "pasted-snippet"

        if file and file.filename:
            file_bytes = await file.read()
            if file_bytes:
                text_content = file_bytes.decode("utf-8", errors="replace")
                source_name = file.filename

        if not text_content and log_text and log_text.strip():
            text_content = log_text.strip()
            source_name = "raw-log-input"

        if not text_content.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No log content provided. Please upload a file or paste log text.",
            )

        raw_lines = text_content.splitlines()

        # Resolve log parser
        p = None
        if format != "auto":
            p = registry.get(format)
        if not p:
            sample = [line for line in raw_lines[:50] if line.strip()]
            p = registry.autodetect(sample) or registry.get("generic")
        if not p:
            p = registry.get("generic")
            if not p:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="No log parser could be resolved.",
                )

        # Ingest and cluster patterns via Drain3 with multiline stack trace grouping
        clusterer = DrainClusterer()
        all_events: list[Event] = []
        total_lines = len(raw_lines)
        parsed_count = 0
        unparsed_count = 0

        for line_num, primary_line, continuations in group_multiline_logs(raw_lines):
            event = p.parse_line(primary_line, line_num)
            if event is None:
                unparsed_count += 1
                continue

            # If there are continuation lines (e.g. stacktrace), preserve them in event fields
            if continuations:
                event_fields = dict(event.fields)
                event_fields["stacktrace"] = "\n".join(continuations)
                event = Event(
                    ts=event.ts,
                    source=event.source,
                    host=event.host,
                    severity_hint=event.severity_hint or "error",
                    message=event.message,
                    fields=event_fields,
                    raw_hash=event.raw_hash,
                )

            parsed_count += 1
            all_events.append(event)
            clusterer.add_event(event)

        clusters = clusterer.get_clusters()

        # Evaluate detection rules
        loaded_rules = get_builtin_rules()
        rule_engine = RuleEngine(loaded_rules)
        findings: list[Finding] = rule_engine.evaluate(all_events, clusters)

        # Optional LLM forensic triage ONLY if security rules fired
        triage_stats = None
        if enable_llm and findings:
            p_inst: LLMProvider
            if provider == "mock":
                p_inst = MockLLMProvider(
                    default_response=LLMAssessment(
                        summary=f"Automated AI triage of {source_name}. Attack indicators classified with high confidence.",
                        attack_type=(
                            "credential_access"
                            if any("bruteforce" in f.rule_ids for f in findings)
                            else "security_anomaly"
                        ),
                        severity="high" if findings else "low",
                        confidence=0.95,
                        evidence=["Suspicious cluster signature detected"],
                        recommended_actions=["Review source IPs and verify firewall drop rules."],
                        false_positive_likelihood="low",
                    )
                )
            else:
                p_inst = get_provider(provider)

            triage_orch = TriageOrchestrator(
                provider=p_inst,
                redactor=Redactor(level="standard"),
            )
            findings, triage_stats = triage_orch.triage(clusters, findings)

        # Build and persist report
        meta = ReportMetadata(
            generated_at=datetime.now(UTC),
            log_source=source_name,
            total_lines=total_lines,
            parsed_events=parsed_count,
            unparsed_lines=unparsed_count,
            total_clusters=len(clusters),
            findings_count=len(findings),
        )
        report = Report(
            metadata=meta,
            findings=findings,
            clusters=clusters,
            stats=triage_stats or {},
        )
        new_run_id = storage.save_run(report)

        # Optional auto-dispatch notification if threats are detected
        if notify_on_complete and findings:
            saved_settings = storage.get_all_settings()
            for ch in ("telegram", "discord", "webhook"):
                try:
                    notif = resolve_notifier(ch, saved_settings)
                    if getattr(notif, "_is_configured", lambda: False)():
                        notif.send_digest(findings, meta)
                except Exception as exc:
                    logger.warning("Auto-dispatch notification to %s failed: %s", ch, exc)

        return RedirectResponse(
            url=f"/runs/{new_run_id}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.get("/settings", response_class=HTMLResponse, dependencies=[Depends(verify_token)])
    def settings_page(request: Request) -> HTMLResponse:
        """Render notification credentials and webhook integration configuration."""
        settings_dict = storage.get_all_settings()
        stats = storage.get_global_stats()
        return templates.TemplateResponse(
            request=request,
            name="settings.html",
            context={
                "settings": settings_dict,
                "saved": False,
                "stats": stats,
            },
        )

    @app.post("/settings", response_class=HTMLResponse, dependencies=[Depends(verify_token)])
    async def settings_save(
        request: Request,
        telegram_bot_token: str = Form(""),
        telegram_chat_id: str = Form(""),
        discord_webhook_url: str = Form(""),
        generic_webhook_url: str = Form(""),
        generic_webhook_secret: str = Form(""),
    ) -> HTMLResponse:
        """Save third-party notification credentials to the local settings store."""
        storage.set_setting("telegram_bot_token", telegram_bot_token.strip())
        storage.set_setting("telegram_chat_id", telegram_chat_id.strip())
        storage.set_setting("discord_webhook_url", discord_webhook_url.strip())
        storage.set_setting("generic_webhook_url", generic_webhook_url.strip())
        storage.set_setting("generic_webhook_secret", generic_webhook_secret.strip())

        settings_dict = storage.get_all_settings()
        stats = storage.get_global_stats()
        return templates.TemplateResponse(
            request=request,
            name="settings.html",
            context={
                "settings": settings_dict,
                "saved": True,
                "stats": stats,
            },
        )

    @app.post("/api/runs/clear", dependencies=[Depends(verify_token)])
    def clear_all_runs(request: Request) -> Response:
        """Purge all historical triage runs and reset dashboard."""
        storage.clear_all_runs()
        if request.headers.get("HX-Request"):
            return Response(headers={"HX-Redirect": "/"})
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/runs/{run_id}/delete", dependencies=[Depends(verify_token)])
    def delete_single_run(request: Request, run_id: str) -> Response:
        """Delete an individual triage run from SQLite."""
        storage.delete_run(run_id)
        if request.headers.get("HX-Request"):
            return Response(headers={"HX-Redirect": "/"})
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/api/notify/test", response_class=HTMLResponse, dependencies=[Depends(verify_token)])
    async def test_notification(
        channel: str = "telegram",
        telegram_bot_token: str | None = Form(None),
        telegram_chat_id: str | None = Form(None),
        discord_webhook_url: str | None = Form(None),
        generic_webhook_url: str | None = Form(None),
        generic_webhook_secret: str | None = Form(None),
    ) -> HTMLResponse:
        """Send a live test alert to verify notification credentials via HTMX."""
        settings = storage.get_all_settings()
        if telegram_bot_token is not None:
            settings["telegram_bot_token"] = telegram_bot_token.strip()
        if telegram_chat_id is not None:
            settings["telegram_chat_id"] = telegram_chat_id.strip()
        if discord_webhook_url is not None:
            settings["discord_webhook_url"] = discord_webhook_url.strip()
        if generic_webhook_url is not None:
            settings["generic_webhook_url"] = generic_webhook_url.strip()
        if generic_webhook_secret is not None:
            settings["generic_webhook_secret"] = generic_webhook_secret.strip()

        try:
            notif = resolve_notifier(channel, settings)
            if hasattr(notif, "cooldown"):
                notif.cooldown.clear()
            test_finding = create_test_finding()
            delivered = notif.send_alert(test_finding)
            if delivered:
                return HTMLResponse(
                    '<span style="color: #10b981; font-weight: 600; font-size: 0.85rem; display: inline-flex; align-items: center; gap: 0.25rem;">'
                    "<span>✓</span> Test Notification Delivered Successfully!"
                    "</span>"
                )
            else:
                return HTMLResponse(
                    '<span style="color: #ef4444; font-weight: 600; font-size: 0.85rem; display: inline-flex; align-items: center; gap: 0.25rem;">'
                    "<span>✗</span> Delivery Failed — Check credentials & chat/webhook permissions."
                    "</span>"
                )
        except Exception as exc:
            return HTMLResponse(
                f'<span style="color: #ef4444; font-weight: 600; font-size: 0.85rem;">'
                f"<span>✗</span> Error: {html.escape(str(exc))}"
                f"</span>"
            )

    @app.get("/runs/{run_id}", response_class=HTMLResponse, dependencies=[Depends(verify_token)])
    def run_detail(request: Request, run_id: str) -> HTMLResponse:
        """Render detailed view for a single triage run."""
        report = storage.get_run(run_id)
        if report is None:
            raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")

        classified_errors = extract_classified_errors(report.clusters)

        return templates.TemplateResponse(
            request=request,
            name="run_detail.html",
            context={
                "run_id": run_id,
                "report": report,
                "classified_errors": classified_errors,
            },
        )

    @app.post(
        "/runs/{run_id}/notify",
        response_class=HTMLResponse,
        dependencies=[Depends(verify_token)],
    )
    def notify_run_digest(
        run_id: str,
        channel: str = "telegram",
    ) -> HTMLResponse:
        """Dispatch a full run digest to Telegram or Discord."""
        report = storage.get_run(run_id)
        if report is None:
            raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")

        settings = storage.get_all_settings()
        notifier = resolve_notifier(channel, settings)
        if hasattr(notifier, "cooldown"):
            notifier.cooldown.clear()

        try:
            delivered = notifier.send_digest(report.findings, report.metadata)
            if delivered:
                msg = f"✓ Run digest dispatched to {channel.capitalize()}!"
                return HTMLResponse(
                    f'<span style="color: #10b981; font-weight: 600; font-size: 0.85rem; border: 1px solid #10b981; padding: 0.25rem 0.5rem; border-radius: 4px; background: rgba(16, 185, 129, 0.1);">{msg}</span>'
                )
            else:
                msg = f"✗ Failed sending to {channel.capitalize()} (unconfigured or rejected)."
                return HTMLResponse(
                    f'<span style="color: #ef4444; font-weight: 600; font-size: 0.85rem; border: 1px solid #ef4444; padding: 0.25rem 0.5rem; border-radius: 4px; background: rgba(239, 68, 68, 0.1);">{msg}</span>'
                )
        except Exception as exc:
            return HTMLResponse(
                f'<span style="color: #ef4444; font-weight: 600; font-size: 0.85rem;">Error: {html.escape(str(exc))}</span>'
            )

    @app.post(
        "/runs/{run_id}/findings/{finding_id}/notify",
        response_class=HTMLResponse,
        dependencies=[Depends(verify_token)],
    )
    def notify_single_finding(
        run_id: str,
        finding_id: str,
        channel: str = "telegram",
    ) -> HTMLResponse:
        """Dispatch an individual finding alert to Telegram or Discord."""
        report = storage.get_run(run_id)
        if report is None:
            raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")

        target_finding = next((f for f in report.findings if f.id == finding_id), None)
        if target_finding is None:
            raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found")

        settings = storage.get_all_settings()
        notifier = resolve_notifier(channel, settings)
        if hasattr(notifier, "cooldown"):
            notifier.cooldown.clear()

        try:
            delivered = notifier.send_alert(target_finding, report.metadata)
            if delivered:
                msg = f"✓ Finding alert delivered to {channel.capitalize()}!"
                return HTMLResponse(
                    f'<span style="color: #10b981; font-weight: 600; font-size: 0.8rem; border: 1px solid #10b981; padding: 0.2rem 0.4rem; border-radius: 4px; background: rgba(16, 185, 129, 0.1);">{msg}</span>'
                )
            else:
                msg = f"✗ Delivery to {channel.capitalize()} failed. Check settings."
                return HTMLResponse(
                    f'<span style="color: #ef4444; font-weight: 600; font-size: 0.8rem; border: 1px solid #ef4444; padding: 0.2rem 0.4rem; border-radius: 4px; background: rgba(239, 68, 68, 0.1);">{msg}</span>'
                )
        except Exception as exc:
            return HTMLResponse(
                f'<span style="color: #ef4444; font-weight: 600; font-size: 0.8rem;">Error: {html.escape(str(exc))}</span>'
            )

    @app.post(
        "/runs/{run_id}/clusters/{cluster_id}/notify",
        response_class=HTMLResponse,
        dependencies=[Depends(verify_token)],
    )
    def notify_cluster_error(
        run_id: str,
        cluster_id: str,
        channel: str = "telegram",
    ) -> HTMLResponse:
        """Dispatch an individual error cluster alert to Telegram or Discord."""
        report = storage.get_run(run_id)
        if report is None:
            raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")

        target_cluster = next((c for c in report.clusters if c.id == cluster_id), None)
        if target_cluster is None:
            raise HTTPException(status_code=404, detail=f"Cluster '{cluster_id}' not found")

        settings = storage.get_all_settings()
        notifier = resolve_notifier(channel, settings)
        if hasattr(notifier, "cooldown"):
            notifier.cooldown.clear()

        synthetic_finding = Finding(
            id=f"err-{cluster_id}",
            cluster_ids=[cluster_id],
            rule_ids=["APPLICATION-ERROR"],
            rule_severity="high",
            llm=LLMAssessment(
                summary=f"Application Error Pattern #{cluster_id}: {target_cluster.template[:120]}",
                attack_type="application_error",
                severity="high",
                confidence=1.0,
                evidence=target_cluster.sample_messages[:2],
                recommended_actions=["Review application logs and service health."],
                false_positive_likelihood="low",
            ),
        )

        try:
            delivered = notifier.send_alert(synthetic_finding, report.metadata)
            if delivered:
                msg = f"✓ Error alert sent to {channel.capitalize()}!"
                return HTMLResponse(
                    f'<span style="color: #10b981; font-weight: 600; font-size: 0.8rem; border: 1px solid #10b981; padding: 0.2rem 0.4rem; border-radius: 4px; background: rgba(16, 185, 129, 0.1);">{msg}</span>'
                )
            else:
                msg = f"✗ Delivery to {channel.capitalize()} failed."
                return HTMLResponse(
                    f'<span style="color: #ef4444; font-weight: 600; font-size: 0.8rem; border: 1px solid #ef4444; padding: 0.2rem 0.4rem; border-radius: 4px; background: rgba(239, 68, 68, 0.1);">{msg}</span>'
                )
        except Exception as exc:
            return HTMLResponse(
                f'<span style="color: #ef4444; font-weight: 600; font-size: 0.8rem;">Error: {html.escape(str(exc))}</span>'
            )

    @app.get(
        "/runs/{run_id}/actions/{target}",
        response_class=PlainTextResponse,
        dependencies=[Depends(verify_token)],
    )
    def export_firewall_actions(
        run_id: str,
        target: str,
    ) -> PlainTextResponse:
        """Generate advisory perimeter firewall mitigation drop rules in plain text."""
        report = storage.get_run(run_id)
        if report is None:
            raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")

        valid_targets = {"nftables", "iptables", "fail2ban", "cloudflare"}
        if target not in valid_targets:
            raise HTTPException(status_code=400, detail=f"Unsupported target format: '{target}'")

        content = generate_action_export(report, target=target)  # type: ignore[arg-type]
        return PlainTextResponse(content)

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

        matched_clusters = [c for c in report.clusters if c.id in target_finding.cluster_ids]
        if not matched_clusters:
            matched_clusters = report.clusters[:2]

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

    @app.post(
        "/runs/{run_id}/clusters/{cluster_id}/explain",
        response_class=HTMLResponse,
        dependencies=[Depends(verify_token)],
    )
    def explain_cluster_on_demand(
        request: Request,
        run_id: str,
        cluster_id: str,
    ) -> HTMLResponse:
        """HTMX endpoint to trigger on-demand AI root cause diagnosis for an application error cluster."""
        report = storage.get_run(run_id)
        if report is None:
            raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")

        target_cluster = next((c for c in report.clusters if c.id == cluster_id), None)
        if target_cluster is None:
            raise HTTPException(status_code=404, detail=f"Cluster '{cluster_id}' not found")

        t_text = target_cluster.template.lower()
        assessment: LLMAssessment | None = None

        # If running mock provider, produce context-aware diagnosis tailored to error signature
        if provider_name == "mock" or isinstance(orchestrator.provider, MockLLMProvider):
            if "curl error" in t_text or "timed out" in t_text or "resolving" in t_text:
                assessment = LLMAssessment(
                    summary=(
                        f"External network or DNS resolution timeout: {target_cluster.template[:120]}. "
                        "The application attempted to communicate with an external API but failed within the timeout window, "
                        "triggering fallback cache/version handling."
                    ),
                    attack_type="network_timeout",
                    severity="high",
                    confidence=0.96,
                    evidence=[
                        "cURL error 28: Resolving timed out after 8000ms",
                        "Fallback versions utilized",
                    ],
                    recommended_actions=[
                        "Verify DNS resolver health in /etc/resolv.conf and test resolution using 'dig' or 'curl -Iv'.",
                        "Confirm outbound HTTPS egress on port 443 to the target endpoint is not blocked by local firewall rules.",
                    ],
                    false_positive_likelihood="low",
                )
            elif "scheduled command" in t_text or "exit code" in t_text or "artisan" in t_text:
                assessment = LLMAssessment(
                    summary=(
                        f"Scheduled background task failure: {target_cluster.template[:120]}. "
                        "Artisan console command terminated unexpectedly with non-zero exit code."
                    ),
                    attack_type="cron_task_failure",
                    severity="high",
                    confidence=0.95,
                    evidence=["Exit code [1] returned by artisan scheduler"],
                    recommended_actions=[
                        "Execute 'php artisan p:egg:update-index -v' in server terminal to view full exception trace.",
                        "Inspect application database connection and credentials.",
                    ],
                    false_positive_likelihood="low",
                )
            else:
                assessment = LLMAssessment(
                    summary=f"Application runtime error detected in mined cluster: {target_cluster.template[:120]}.",
                    attack_type="application_error",
                    severity="medium",
                    confidence=0.90,
                    evidence=target_cluster.sample_messages[:2],
                    recommended_actions=[
                        "Inspect application logs for preceding warning or database failure context.",
                        "Verify service dependencies and configuration.",
                    ],
                    false_positive_likelihood="low",
                )
        else:
            synthetic_finding = Finding(
                id=f"explain-{cluster_id}",
                cluster_ids=[cluster_id],
                rule_ids=[],
                rule_severity="medium",
            )
            triaged_findings, _ = orchestrator.triage([target_cluster], [synthetic_finding])
            assessment = triaged_findings[0].llm if triaged_findings else None

        if assessment:
            actions_html = ""
            if assessment.recommended_actions:
                items = "".join(
                    f"<li>{html.escape(a)}</li>" for a in assessment.recommended_actions[:2]
                )
                actions_html = (
                    f'<div style="margin-top: 0.4rem;">'
                    f'<div style="font-size: 0.7rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase;">'
                    f"Fix / Remediation"
                    f"</div>"
                    f'<ul style="padding-left: 1.1rem; font-size: 0.8rem; color: #6ee7b7; margin: 0;">{items}</ul>'
                    f"</div>"
                )

            html_content = (
                f'<div style="background: var(--bg-card); border-radius: 6px; padding: 0.85rem; border: 1px solid var(--border-subtle);">'
                f'<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">'
                f'<div style="font-weight: 600; font-size: 0.85rem; color: var(--text-main);">AI Root Cause Diagnosis</div>'
                f'<span class="badge badge-info" style="font-size: 0.7rem;">Confidence: {int(assessment.confidence * 100)}%</span>'
                f"</div>"
                f'<p style="font-size: 0.85rem; line-height: 1.4; color: var(--text-main); margin: 0 0 0.4rem 0;">{html.escape(assessment.summary)}</p>'
                f"{actions_html}"
                f"</div>"
            )
        else:
            html_content = '<div style="color: var(--text-muted); font-size: 0.8rem;">Diagnosis not available.</div>'

        return HTMLResponse(content=html_content)

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
