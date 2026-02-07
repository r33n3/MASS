"""Scan execution service.

Bridges API layer with orchestration layer, managing the execution
of security scans and storage of results.
"""

import asyncio
import concurrent.futures
import json
import logging
from datetime import datetime

from mass.orchestration.service import ScanService, ScanResult

# Expand default thread pool so 10+ concurrent scans don't exhaust it.
# Each scan runs synchronous file I/O in asyncio.to_thread().
_scan_thread_pool = concurrent.futures.ThreadPoolExecutor(
    max_workers=20,
    thread_name_prefix="mass-scan",
)
from mass.storage.database import get_session, get_session_factory
from mass.storage.models.deployment import Scan, ScanStatus
from mass.storage.models.finding import Finding as DBFinding
from mass.storage.repositories.scan import ScanRepository
from mass.storage.repositories.finding import FindingRepository
from mass.storage.repositories.deployment import DeploymentRepository

logger = logging.getLogger(__name__)


class ScanExecutionService:
    """Service for executing scans and storing results.

    This service bridges the gap between:
    - API layer (database models, repositories)
    - Orchestration layer (ScanService, analyzers)

    Creates its own database session for background task execution,
    since FastAPI request sessions close after the response is sent.
    """

    def __init__(self) -> None:
        self.scan_service = ScanService()

    async def execute_scan(self, scan_id: str) -> None:
        """Execute a scan asynchronously in a background task.

        Creates its own database session to avoid SQLAlchemy async
        context issues with FastAPI BackgroundTasks.

        Args:
            scan_id: ID of scan to execute
        """
        async with get_session() as session:
            scan_repo = ScanRepository(session)
            deployment_repo = DeploymentRepository(session)

            try:
                # Load scan
                scan = await scan_repo.get(scan_id)
                if not scan:
                    logger.error(f"Scan {scan_id} not found")
                    return

                tenant_id = scan.tenant_id

                # Update status to running and commit immediately
                # so external consumers can see the scan is active
                scan.status = ScanStatus.RUNNING.value
                scan.started_at = datetime.utcnow()
                await session.commit()

                # Publish SCAN_STARTED event
                try:
                    from mass.core.events import get_event_bus, Event, EventType
                    await get_event_bus().publish(Event(
                        type=EventType.SCAN_STARTED,
                        data={"scan_id": scan_id, "deployment_id": scan.deployment_id},
                        tenant_id=tenant_id,
                    ))
                except Exception:
                    logger.debug("Failed to publish SCAN_STARTED event", exc_info=True)

                # Load deployment to get source_path and target configuration
                deployment = await deployment_repo.get(scan.deployment_id)
                if not deployment:
                    raise ValueError(
                        f"Deployment {scan.deployment_id} not found"
                    )

                source_path = deployment.source_path
                profile_name = scan.profile or "standard"

                # Extract model config from deployment metadata
                import json as _json
                deploy_meta = {}
                if deployment.meta:
                    try:
                        deploy_meta = _json.loads(deployment.meta)
                    except (ValueError, TypeError):
                        pass

                # Load remediation templates into cache for the scan pipeline
                from mass.orchestration.remediation_resolver import load_remediation_cache
                remediation_cache = await load_remediation_cache(session)

                # Create progress bridge for sync-to-async communication
                from mass.orchestration.progress_bridge import ProgressBridge
                loop = asyncio.get_running_loop()
                session_factory = get_session_factory()
                bridge = ProgressBridge(
                    scan_id=scan_id,
                    tenant_id=tenant_id,
                    loop=loop,
                    session_factory=session_factory,
                )

                # Extract target configuration from deployment metadata
                target_type = deploy_meta.get("target_type", "deployment")
                target_files = deploy_meta.get("target_files")
                inline_content = deploy_meta.get("inline_content")

                # For non-deployment targets, source_path is optional
                if not source_path and target_type == "deployment":
                    raise ValueError(
                        f"Deployment {scan.deployment_id} has no source_path"
                    )

                logger.info(
                    f"Starting scan {scan_id} on {source_path or 'inline'} "
                    f"(target_type={target_type}) with profile '{profile_name}'"
                )

                # Build agent metadata for agent_endpoint targets
                agent_meta = None
                if target_type == "agent_endpoint":
                    agent_meta = {
                        k: deploy_meta[k]
                        for k in (
                            "agent_url", "agent_protocol",
                            "agent_auth_type", "agent_auth_token",
                            "upstream_agents", "downstream_agents",
                        )
                        if k in deploy_meta
                    }

                # Execute scan in dedicated thread pool (ScanService is synchronous).
                # Uses _scan_thread_pool (20 threads) instead of the default
                # executor to avoid exhaustion under 10+ concurrent scans.
                scan_result: ScanResult = await loop.run_in_executor(
                    _scan_thread_pool,
                    lambda: self.scan_service.scan_deployment(
                        source_path or "",
                        profile_name,
                        deployment.name,
                        on_progress=bridge.on_progress,
                        on_findings=bridge.store_findings,
                        model_endpoint=deploy_meta.get("model_endpoint"),
                        model_provider=deploy_meta.get("model_provider"),
                        model_name=deploy_meta.get("model_name"),
                        model_api_key=deploy_meta.get("model_api_key"),
                        system_prompt=deploy_meta.get("system_prompt"),
                        remediation_cache=remediation_cache,
                        target_type=target_type,
                        target_files=target_files,
                        inline_content=inline_content,
                        agent_meta=agent_meta,
                    ),
                )

                # Update scan with final results
                # Re-fetch scan to get latest state (bridge may have updated it)
                scan = await scan_repo.get(scan_id)
                if scan:
                    scan.status = ScanStatus.COMPLETED.value
                    scan.completed_at = datetime.utcnow()
                    scan.progress_percent = 100.0
                    scan.current_phase = "completed"
                    if scan.started_at:
                        scan.duration_seconds = int(
                            (scan.completed_at - scan.started_at).total_seconds()
                        )
                    # Finding counts were updated incrementally by the bridge;
                    # set final counts from ScanResult as the authoritative source
                    summary = scan_result.summary
                    scan.total_findings = len(scan_result.findings)
                    scan.critical_findings = summary.critical_count if summary else 0
                    scan.high_findings = summary.high_count if summary else 0
                    scan.medium_findings = summary.medium_count if summary else 0
                    scan.low_findings = summary.low_count if summary else 0

                    await session.commit()

                # Run Final Verdict Judge — holistic post-scan analysis
                try:
                    scan.current_phase = "generating_verdict"
                    await session.commit()

                    from mass.orchestration.judge import FinalJudge

                    judge = FinalJudge(
                        provider=deploy_meta.get("model_provider", "ollama"),
                        model=deploy_meta.get("model_name"),
                    )

                    # Serialize findings for the evidence brief
                    serialized_findings = []
                    for f in scan_result.findings:
                        serialized_findings.append(f.model_dump(
                            include={
                                "title", "description", "severity", "category",
                                "component_type", "component_name", "confidence",
                                "metadata", "cwe_ids", "owasp_ids",
                            }
                        ))

                    # Build progressive threat model (Phases 1-3)
                    tm_builder = None
                    try:
                        from mass.threat_model.builder import ThreatModelBuilder
                        from mass.orchestration.judge import _infer_deployment_posture

                        tm_builder = ThreatModelBuilder(deployment.name)

                        # Phase 1: Discovery
                        posture = _infer_deployment_posture(
                            scan_result.metadata.get("environment", {}),
                            scan_result.metadata.get("topology", {}),
                            deploy_meta,
                            serialized_findings,
                        )
                        tm_builder.ingest_discovery(
                            environment=scan_result.metadata.get("environment", {}),
                            topology=scan_result.metadata.get("topology", {}),
                            attack_surface=None,
                            deployment_posture=posture,
                        )

                        # Phase 2: Static findings
                        tm_builder.ingest_findings(serialized_findings)

                        # Phase 3: Interrogation (confirmed findings + risk score)
                        if scan_result.metadata.get("risk_score"):
                            confirmed = [
                                f for f in serialized_findings
                                if f.get("metadata", {}).get("confidence_level") == "confirmed"
                            ]
                            tm_builder.ingest_interrogation(
                                risk_score=scan_result.metadata.get("risk_score"),
                                findings=confirmed,
                            )
                    except Exception:
                        logger.debug("Threat model construction failed (non-fatal)", exc_info=True)
                        tm_builder = None

                    brief = judge.assemble_evidence(
                        scan_id=scan_id,
                        deployment_name=deployment.name,
                        profile=profile_name,
                        duration_seconds=scan.duration_seconds or 0,
                        findings=serialized_findings,
                        risk_score=scan_result.metadata.get("risk_score"),
                        target_info={
                            "target_type": target_type,
                            "model_provider": deploy_meta.get("model_provider"),
                            "model_name": deploy_meta.get("model_name"),
                            "model_endpoint": deploy_meta.get("model_endpoint"),
                            "agent_url": deploy_meta.get("agent_url"),
                        },
                        environment=scan_result.metadata.get("environment"),
                        topology=scan_result.metadata.get("topology"),
                    )

                    verdict = await loop.run_in_executor(
                        _scan_thread_pool,
                        lambda: judge.judge(brief),
                    )

                    scan.verdict = verdict.to_json()
                    scan.current_phase = "completed"
                    await session.commit()

                    logger.info(
                        "Scan %s verdict: %s (risk_level=%s, confidence=%.2f)",
                        scan_id,
                        verdict.overall_assessment[:80],
                        verdict.risk_level,
                        verdict.confidence,
                    )

                    # Broadcast verdict via WebSocket
                    try:
                        from mass.dashboard.websocket import broadcast_verdict_ready
                        await broadcast_verdict_ready(
                            scan_id=scan_id,
                            risk_level=verdict.risk_level,
                            overall_assessment=verdict.overall_assessment,
                        )
                    except Exception:
                        logger.debug("Failed to broadcast verdict", exc_info=True)

                except Exception:
                    logger.warning(
                        "Scan %s: verdict generation failed (non-fatal)",
                        scan_id,
                        exc_info=True,
                    )

                # Phase 4: Integrate verdict into threat model and finalize
                if tm_builder is not None:
                    try:
                        if scan.verdict:
                            verdict_data = json.loads(scan.verdict)
                            tm_builder.ingest_verdict(verdict_data)
                        threat_model_obj = tm_builder.build()
                        scan.threat_model = json.dumps(threat_model_obj.to_dict())
                        await session.commit()
                        logger.info(
                            "Scan %s threat model: %s (%d threats, data_class=%s)",
                            scan_id,
                            threat_model_obj.overall_risk_level,
                            len(threat_model_obj.threats),
                            threat_model_obj.data_classification.value,
                        )
                        # Broadcast threat model via WebSocket
                        try:
                            from mass.dashboard.websocket import broadcast_threat_model_ready
                            await broadcast_threat_model_ready(
                                scan_id=scan_id,
                                overall_risk_level=threat_model_obj.overall_risk_level,
                                total_threats=len(threat_model_obj.threats),
                                data_classification=threat_model_obj.data_classification.value,
                            )
                        except Exception:
                            logger.debug("Failed to broadcast threat model", exc_info=True)

                    except Exception:
                        logger.debug(
                            "Threat model finalization failed (non-fatal)",
                            exc_info=True,
                        )

                # Persist discovered environment + topology to deployment metadata
                # so the dashboard and API can serve topology without re-scanning.
                if scan_result.metadata.get("environment") or scan_result.metadata.get("topology"):
                    try:
                        deployment = await deployment_repo.get(scan.deployment_id)
                        if deployment:
                            current_meta = {}
                            if deployment.meta:
                                try:
                                    current_meta = json.loads(deployment.meta)
                                except (ValueError, TypeError):
                                    pass
                            if scan_result.metadata.get("environment"):
                                current_meta["environment"] = scan_result.metadata["environment"]
                            if scan_result.metadata.get("topology"):
                                current_meta["topology"] = scan_result.metadata["topology"]
                            deployment.meta = json.dumps(current_meta)
                            await session.flush()
                            logger.info(
                                "Persisted environment (%s) and topology (%d nodes) "
                                "to deployment %s",
                                scan_result.metadata.get("environment", {}).get("cloud_provider", "?"),
                                len(scan_result.metadata.get("topology", {}).get("nodes", [])),
                                scan.deployment_id,
                            )
                    except Exception:
                        logger.debug("Failed to persist topology to deployment", exc_info=True)

                # Auto-close findings from previous scan that no longer appear
                try:
                    from mass.api.services.finding_lifecycle import auto_close_findings
                    closed_count = await auto_close_findings(
                        session=session,
                        completed_scan_id=scan_id,
                        deployment_id=scan.deployment_id,
                    )
                    if closed_count > 0:
                        logger.info(
                            "Auto-closed %d findings for deployment %s",
                            closed_count, scan.deployment_id,
                        )
                except Exception:
                    logger.debug("Auto-close findings failed (non-fatal)", exc_info=True)

                logger.info(
                    f"Scan {scan_id} completed: {len(scan_result.findings)} findings "
                    f"in {scan.duration_seconds if scan else '?'}s"
                )

                # Broadcast completion via WebSocket
                try:
                    from mass.dashboard.websocket import broadcast_scan_complete
                    await broadcast_scan_complete(
                        scan_id=scan_id,
                        status="completed",
                        duration_seconds=scan.duration_seconds or 0,
                        findings_count=len(scan_result.findings),
                    )
                except Exception:
                    logger.debug("Failed to broadcast scan completion", exc_info=True)

                # Publish SCAN_COMPLETED event
                try:
                    from mass.core.events import get_event_bus, Event, EventType
                    await get_event_bus().publish(Event(
                        type=EventType.SCAN_COMPLETED,
                        data={
                            "scan_id": scan_id,
                            "deployment_id": scan.deployment_id,
                            "findings_count": len(scan_result.findings),
                            "duration_seconds": scan.duration_seconds,
                        },
                        tenant_id=tenant_id,
                    ))
                except Exception:
                    logger.debug("Failed to publish SCAN_COMPLETED event", exc_info=True)

            except Exception as e:
                logger.exception(f"Scan {scan_id} failed: {e}")
                try:
                    scan = await scan_repo.get(scan_id)
                    if scan:
                        scan.status = ScanStatus.FAILED.value
                        scan.error_message = str(e)
                        scan.completed_at = datetime.utcnow()
                        scan.progress_percent = 0.0
                        if scan.started_at:
                            scan.duration_seconds = int(
                                (scan.completed_at - scan.started_at).total_seconds()
                            )
                        await session.commit()

                    # Broadcast failure via WebSocket
                    try:
                        from mass.dashboard.websocket import broadcast_scan_complete
                        await broadcast_scan_complete(
                            scan_id=scan_id,
                            status="failed",
                            duration_seconds=scan.duration_seconds or 0 if scan else 0,
                            findings_count=0,
                        )
                    except Exception:
                        logger.debug("Failed to broadcast scan failure", exc_info=True)

                    # Publish SCAN_FAILED event
                    try:
                        from mass.core.events import get_event_bus, Event, EventType
                        await get_event_bus().publish(Event(
                            type=EventType.SCAN_FAILED,
                            data={"scan_id": scan_id, "error": str(e)},
                            tenant_id=tenant_id,
                        ))
                    except Exception:
                        logger.debug("Failed to publish SCAN_FAILED event", exc_info=True)

                except Exception as update_error:
                    logger.exception(f"Failed to update scan status: {update_error}")
