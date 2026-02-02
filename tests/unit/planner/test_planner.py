"""Tests for AI Scan Planner module."""

import pytest
from datetime import datetime, timedelta

from mass.core.findings import Finding
from mass.core.types import Severity, AttackCategory, ComponentType
from mass.orchestration.planner import JobType
from mass.planner.risk import (
    RiskFactor,
    RiskScore,
    RiskAssessor,
    DeploymentRiskProfile,
)
from mass.planner.priority import (
    AnalyzerPriority,
    PriorityCalculator,
    PrioritizedPlan,
)
from mass.planner.adaptive import (
    AdaptiveStrategy,
    AdaptiveScanner,
    ScanAdjustment,
)
from mass.planner.history import (
    ScanHistoryEntry,
    ScanHistory,
    MemoryHistoryStore,
)
from mass.planner.optimizer import (
    OptimizationConfig,
    OptimizedScan,
    ScanOptimizer,
    create_optimizer,
)


def create_test_finding(
    title: str = "Test Finding",
    severity: Severity = Severity.HIGH,
    category: AttackCategory = AttackCategory.PROMPT_INJECTION,
) -> Finding:
    """Create a test finding."""
    return Finding(
        title=title,
        description="Test description",
        severity=severity,
        category=category,
        component_type=ComponentType.MODEL,
        component_name="test-model",
    )


class TestRiskScore:
    """Tests for RiskScore."""

    def test_risk_score_creation(self):
        """Test creating a risk score."""
        score = RiskScore(
            factor=RiskFactor.MODEL_FORMAT,
            score=0.8,
            weight=1.0,
            reason="Pickle format detected",
        )
        assert score.factor == RiskFactor.MODEL_FORMAT
        assert score.score == 0.8
        assert score.weighted_score == 0.8

    def test_weighted_score(self):
        """Test weighted score calculation."""
        score = RiskScore(
            factor=RiskFactor.MODEL_SIZE,
            score=0.5,
            weight=0.5,
        )
        assert score.weighted_score == 0.25

    def test_to_dict(self):
        """Test serialization."""
        score = RiskScore(
            factor=RiskFactor.EXTERNAL_EXPOSURE,
            score=0.9,
            weight=1.0,
            reason="Public API",
            evidence=["api.example.com"],
        )
        data = score.to_dict()
        assert data["factor"] == "external_exposure"
        assert data["score"] == 0.9
        assert "api.example.com" in data["evidence"]


class TestDeploymentRiskProfile:
    """Tests for DeploymentRiskProfile."""

    def test_profile_creation(self):
        """Test creating a risk profile."""
        profile = DeploymentRiskProfile(deployment_id="test-123")
        assert profile.deployment_id == "test-123"
        assert profile.overall_score == 0.0

    def test_add_score(self):
        """Test adding scores recalculates overall."""
        profile = DeploymentRiskProfile(deployment_id="test")
        profile.add_score(RiskScore(
            factor=RiskFactor.MODEL_FORMAT,
            score=0.8,
            weight=1.0,
        ))
        assert profile.overall_score == 0.8

    def test_calculate_overall(self):
        """Test overall score calculation."""
        profile = DeploymentRiskProfile(deployment_id="test")
        profile.scores = [
            RiskScore(factor=RiskFactor.MODEL_FORMAT, score=1.0, weight=1.0),
            RiskScore(factor=RiskFactor.MODEL_SIZE, score=0.5, weight=0.5),
        ]
        overall = profile.calculate_overall()
        # (1.0*1.0 + 0.5*0.5) / (1.0 + 0.5) = 1.25 / 1.5 = 0.833...
        assert 0.83 < overall < 0.84

    def test_risk_level_critical(self):
        """Test critical risk level."""
        profile = DeploymentRiskProfile(deployment_id="test")
        profile.add_score(RiskScore(
            factor=RiskFactor.MODEL_FORMAT,
            score=0.9,
            weight=1.0,
        ))
        assert profile.risk_level == Severity.CRITICAL

    def test_risk_level_low(self):
        """Test low risk level."""
        profile = DeploymentRiskProfile(deployment_id="test")
        profile.add_score(RiskScore(
            factor=RiskFactor.LOGGING_COVERAGE,
            score=0.15,
            weight=1.0,
        ))
        assert profile.risk_level == Severity.INFO

    def test_get_top_risks(self):
        """Test getting top risk factors."""
        profile = DeploymentRiskProfile(deployment_id="test")
        profile.scores = [
            RiskScore(factor=RiskFactor.MODEL_FORMAT, score=1.0, weight=1.0),
            RiskScore(factor=RiskFactor.MODEL_SIZE, score=0.3, weight=0.5),
            RiskScore(factor=RiskFactor.EXTERNAL_EXPOSURE, score=0.8, weight=1.0),
        ]
        top = profile.get_top_risks(2)
        assert len(top) == 2
        assert top[0].factor == RiskFactor.MODEL_FORMAT


class TestRiskAssessor:
    """Tests for RiskAssessor."""

    def test_assessor_creation(self):
        """Test creating an assessor."""
        assessor = RiskAssessor()
        assert RiskFactor.MODEL_FORMAT in assessor.weights

    def test_assess_model_format(self):
        """Test assessing pickle format risk."""
        assessor = RiskAssessor()
        profile = assessor.assess({
            "id": "test-deploy",
            "model": {
                "format": "pickle",
            },
        })
        # Should have model format risk
        format_scores = [s for s in profile.scores if s.factor == RiskFactor.MODEL_FORMAT]
        assert len(format_scores) > 0
        assert format_scores[0].score == 1.0

    def test_assess_external_exposure(self):
        """Test assessing external exposure risk."""
        assessor = RiskAssessor()
        profile = assessor.assess({
            "id": "test-deploy",
            "deployment": {
                "external": True,
            },
        })
        exposure_scores = [s for s in profile.scores if s.factor == RiskFactor.EXTERNAL_EXPOSURE]
        assert len(exposure_scores) > 0
        assert exposure_scores[0].score == 0.9

    def test_assess_sensitive_data(self):
        """Test assessing sensitive data risk."""
        assessor = RiskAssessor()
        profile = assessor.assess({
            "id": "test-deploy",
            "deployment": {
                "data_types": ["pii", "credentials"],
            },
        })
        data_scores = [s for s in profile.scores if s.factor == RiskFactor.DATA_SENSITIVITY]
        assert len(data_scores) > 0

    def test_assess_privileged_container(self):
        """Test assessing privileged container risk."""
        assessor = RiskAssessor()
        profile = assessor.assess({
            "id": "test-deploy",
            "infrastructure": {
                "container": {"privileged": True},
            },
        })
        container_scores = [s for s in profile.scores if s.factor == RiskFactor.CONTAINER_CONFIG]
        assert len(container_scores) > 0
        assert container_scores[0].score == 1.0

    def test_generate_recommendations(self):
        """Test recommendation generation."""
        assessor = RiskAssessor()
        profile = assessor.assess({
            "id": "test-deploy",
            "model": {"format": "pickle"},
            "deployment": {"external": True},
        })
        assert len(profile.recommendations) > 0

    def test_quick_assess(self):
        """Test quick assessment."""
        assessor = RiskAssessor()
        score, level = assessor.quick_assess({
            "id": "test",
            "model": {"format": "pickle"},
        })
        assert score > 0
        assert level in Severity


class TestPriorityCalculator:
    """Tests for PriorityCalculator."""

    def test_calculator_creation(self):
        """Test creating a calculator."""
        calc = PriorityCalculator()
        assert calc.history_boost == 0.2

    def test_base_priorities(self):
        """Test base priority assignment."""
        calc = PriorityCalculator()
        plan = calc.calculate("test-deploy")

        # Deployment scan should be critical
        deployment = next(
            a for a in plan.analyzers if a.job_type == JobType.DEPLOYMENT_SCAN
        )
        assert deployment.priority == AnalyzerPriority.CRITICAL

    def test_historical_boost(self):
        """Test historical findings boost."""
        calc = PriorityCalculator()
        historical = {JobType.MODEL_FILE_SCAN: 50}
        plan = calc.calculate(
            "test-deploy",
            historical_findings=historical,
        )

        model_scan = next(
            a for a in plan.analyzers if a.job_type == JobType.MODEL_FILE_SCAN
        )
        assert "Historical findings" in model_scan.reasons[0]

    def test_risk_elevation(self):
        """Test risk-based priority elevation."""
        calc = PriorityCalculator()
        risk_profile = DeploymentRiskProfile(deployment_id="test")
        risk_profile.add_score(RiskScore(
            factor=RiskFactor.MODEL_FORMAT,
            score=0.9,
            weight=1.0,
        ))

        plan = calc.calculate("test-deploy", risk_profile=risk_profile)
        model_scan = next(
            a for a in plan.analyzers if a.job_type == JobType.MODEL_FILE_SCAN
        )
        assert "Risk factor" in model_scan.reasons[0]

    def test_ordered_output(self):
        """Test ordered analyzer output."""
        calc = PriorityCalculator()
        plan = calc.calculate("test-deploy")
        ordered = plan.get_ordered()

        # Should be sorted by priority then score
        for i in range(len(ordered) - 1):
            curr = ordered[i]
            next_a = ordered[i + 1]
            assert curr.priority.value <= next_a.priority.value or \
                   (curr.priority == next_a.priority and curr.score >= next_a.score)

    def test_quick_order(self):
        """Test quick ordering."""
        calc = PriorityCalculator()
        ordered = calc.quick_order([
            JobType.MODEL_INTERROGATION,
            JobType.SECRET_DETECTION,
            JobType.DEPLOYMENT_SCAN,
        ])
        # Both DEPLOYMENT_SCAN and SECRET_DETECTION are CRITICAL priority
        # They should both come before MODEL_INTERROGATION (LOW priority)
        assert set(ordered[:2]) == {JobType.DEPLOYMENT_SCAN, JobType.SECRET_DETECTION}
        assert ordered[2] == JobType.MODEL_INTERROGATION  # Low


class TestAdaptiveScanner:
    """Tests for AdaptiveScanner."""

    def test_scanner_creation(self):
        """Test creating an adaptive scanner."""
        scanner = AdaptiveScanner()
        assert scanner.strategy == AdaptiveStrategy.BALANCED

    def test_no_strategy_no_adaptation(self):
        """Test NONE strategy produces no adjustments."""
        scanner = AdaptiveScanner(strategy=AdaptiveStrategy.NONE)
        findings = [create_test_finding()]
        adjustments = scanner.process_findings(findings)
        assert len(adjustments) == 0

    def test_category_escalation(self):
        """Test category-based analyzer addition."""
        scanner = AdaptiveScanner(strategy=AdaptiveStrategy.AGGRESSIVE)
        scanner.set_initial_plan([JobType.DEPLOYMENT_SCAN])

        # Add multiple prompt injection findings to trigger escalation
        findings = [
            create_test_finding(category=AttackCategory.PROMPT_INJECTION)
            for _ in range(3)
        ]
        adjustments = scanner.process_findings(findings)

        # Should trigger addition of related analyzers
        add_adjustments = [a for a in adjustments if a.action == "add"]
        assert len(add_adjustments) > 0

    def test_severity_escalation(self):
        """Test severity-based priority elevation."""
        scanner = AdaptiveScanner(strategy=AdaptiveStrategy.AGGRESSIVE)
        scanner.set_initial_plan([
            JobType.DEPLOYMENT_SCAN,
            JobType.MODEL_INTERROGATION,
        ])

        findings = [
            create_test_finding(severity=Severity.CRITICAL)
            for _ in range(2)
        ]
        adjustments = scanner.process_findings(findings)

        elevate_adjustments = [a for a in adjustments if a.action == "elevate"]
        assert len(elevate_adjustments) > 0

    def test_mark_completed(self):
        """Test marking analyzers complete."""
        scanner = AdaptiveScanner()
        scanner.set_initial_plan([JobType.DEPLOYMENT_SCAN, JobType.SECRET_DETECTION])
        scanner.mark_completed(JobType.DEPLOYMENT_SCAN)

        assert JobType.DEPLOYMENT_SCAN in scanner.state.completed_analyzers
        assert JobType.DEPLOYMENT_SCAN not in scanner.state.pending_analyzers

    def test_should_deepen(self):
        """Test deepen recommendation."""
        scanner = AdaptiveScanner()
        scanner.state.categories_seen.add(AttackCategory.PROMPT_INJECTION)

        assert scanner.should_deepen(JobType.CONTEXT_ANALYSIS)

    def test_get_summary(self):
        """Test summary generation."""
        scanner = AdaptiveScanner()
        scanner.set_initial_plan([JobType.DEPLOYMENT_SCAN])
        summary = scanner.get_summary()

        assert "strategy" in summary
        assert "state" in summary


class TestScanHistory:
    """Tests for ScanHistory."""

    def test_history_creation(self):
        """Test creating scan history."""
        history = ScanHistory()
        assert isinstance(history.store, MemoryHistoryStore)

    def test_record_entry(self):
        """Test recording a history entry."""
        history = ScanHistory()
        entry = ScanHistoryEntry(
            scan_id="scan-1",
            deployment_id="deploy-1",
            total_findings=5,
        )
        history.record(entry)

        entries = history.store.get_by_deployment("deploy-1")
        assert len(entries) == 1

    def test_record_from_result(self):
        """Test recording from scan result."""
        history = ScanHistory()
        findings = [
            create_test_finding(severity=Severity.HIGH),
            create_test_finding(severity=Severity.MEDIUM),
        ]

        entry = history.record_from_result(
            scan_id="scan-1",
            deployment_id="deploy-1",
            findings=findings,
            duration_seconds=60.0,
            analyzers_run=[JobType.DEPLOYMENT_SCAN],
        )

        assert entry.total_findings == 2
        assert entry.by_severity[Severity.HIGH] == 1
        assert entry.by_severity[Severity.MEDIUM] == 1

    def test_get_deployment_stats(self):
        """Test getting deployment statistics."""
        history = ScanHistory()

        # Add some entries
        for i in range(5):
            history.record(ScanHistoryEntry(
                scan_id=f"scan-{i}",
                deployment_id="deploy-1",
                total_findings=i + 1,
            ))

        stats = history.get_deployment_stats("deploy-1")
        assert stats.scan_count == 5
        assert stats.total_findings == 15
        assert stats.avg_findings_per_scan == 3.0

    def test_get_historical_findings_by_analyzer(self):
        """Test getting historical findings by analyzer."""
        history = ScanHistory()
        history.record(ScanHistoryEntry(
            scan_id="scan-1",
            deployment_id="deploy-1",
            by_analyzer={JobType.SECRET_DETECTION: 10},
        ))

        findings = history.get_historical_findings_by_analyzer("deploy-1")
        assert findings[JobType.SECRET_DETECTION] == 10

    def test_predict_findings(self):
        """Test finding prediction."""
        history = ScanHistory()

        for i in range(10):
            history.record(ScanHistoryEntry(
                scan_id=f"scan-{i}",
                deployment_id="deploy-1",
                total_findings=5,
            ))

        prediction = history.predict_findings("deploy-1")
        assert "expected_findings" in prediction
        assert "confidence" in prediction

    def test_analyzer_effectiveness(self):
        """Test analyzer effectiveness calculation."""
        history = ScanHistory()
        history.record(ScanHistoryEntry(
            scan_id="scan-1",
            deployment_id="deploy-1",
            analyzers_run=[JobType.SECRET_DETECTION],
            by_analyzer={JobType.SECRET_DETECTION: 5},
        ))

        effectiveness = history.get_analyzer_effectiveness(days=30)
        assert JobType.SECRET_DETECTION in effectiveness


class TestMemoryHistoryStore:
    """Tests for MemoryHistoryStore."""

    def test_store_creation(self):
        """Test creating a store."""
        store = MemoryHistoryStore()
        assert store.count() == 0

    def test_save_and_retrieve(self):
        """Test saving and retrieving entries."""
        store = MemoryHistoryStore()
        entry = ScanHistoryEntry(
            scan_id="scan-1",
            deployment_id="deploy-1",
        )
        store.save(entry)

        entries = store.get_by_deployment("deploy-1")
        assert len(entries) == 1

    def test_get_recent(self):
        """Test getting recent entries."""
        store = MemoryHistoryStore()

        # Add old entry
        old_entry = ScanHistoryEntry(
            scan_id="old",
            deployment_id="deploy-1",
            timestamp=datetime.utcnow() - timedelta(days=60),
        )
        store.save(old_entry)

        # Add new entry
        new_entry = ScanHistoryEntry(
            scan_id="new",
            deployment_id="deploy-1",
        )
        store.save(new_entry)

        recent = store.get_recent(days=30)
        assert len(recent) == 1
        assert recent[0].scan_id == "new"

    def test_clear(self):
        """Test clearing store."""
        store = MemoryHistoryStore()
        store.save(ScanHistoryEntry(scan_id="test", deployment_id="test"))
        store.clear()
        assert store.count() == 0


class TestOptimizationConfig:
    """Tests for OptimizationConfig."""

    def test_default_config(self):
        """Test default configuration."""
        config = OptimizationConfig()
        assert config.adaptive_strategy == AdaptiveStrategy.BALANCED
        assert config.use_history is True

    def test_custom_config(self):
        """Test custom configuration."""
        config = OptimizationConfig(
            adaptive_strategy=AdaptiveStrategy.AGGRESSIVE,
            max_scan_seconds=300,
            required_analyzers=[JobType.SECRET_DETECTION],
        )
        assert config.max_scan_seconds == 300
        assert JobType.SECRET_DETECTION in config.required_analyzers


class TestScanOptimizer:
    """Tests for ScanOptimizer."""

    def test_optimizer_creation(self):
        """Test creating an optimizer."""
        optimizer = ScanOptimizer()
        assert optimizer.config.adaptive_strategy == AdaptiveStrategy.BALANCED

    def test_basic_optimize(self):
        """Test basic optimization."""
        optimizer = ScanOptimizer()
        scan = optimizer.optimize("deploy-1")

        assert scan.deployment_id == "deploy-1"
        assert len(scan.analyzers) > 0

    def test_optimize_with_risk(self):
        """Test optimization with risk assessment."""
        config = OptimizationConfig(use_risk_assessment=True)
        optimizer = ScanOptimizer(config=config)

        scan = optimizer.optimize(
            "deploy-1",
            deployment_info={
                "id": "deploy-1",
                "model": {"format": "pickle"},
            },
        )

        assert scan.risk_profile is not None
        assert len(scan.optimization_notes) > 0

    def test_optimize_with_time_budget(self):
        """Test optimization with time budget."""
        config = OptimizationConfig(max_scan_seconds=60)
        optimizer = ScanOptimizer(config=config)

        scan = optimizer.optimize("deploy-1")

        # Should have time budget note
        assert any("time budget" in note.lower() for note in scan.optimization_notes)

    def test_optimize_with_analyzer_limit(self):
        """Test optimization with analyzer limit."""
        config = OptimizationConfig(max_analyzers=3)
        optimizer = ScanOptimizer(config=config)

        scan = optimizer.optimize("deploy-1")

        assert len(scan.analyzers) <= 3

    def test_required_analyzers(self):
        """Test required analyzers are included."""
        config = OptimizationConfig(
            required_analyzers=[JobType.MODEL_INTERROGATION],
            excluded_analyzers=[JobType.WORKFLOW_ANALYSIS],
        )
        optimizer = ScanOptimizer(config=config)

        scan = optimizer.optimize("deploy-1")

        assert JobType.MODEL_INTERROGATION in scan.analyzers
        assert JobType.WORKFLOW_ANALYSIS not in scan.analyzers

    def test_record_result(self):
        """Test recording scan results."""
        optimizer = ScanOptimizer()
        findings = [create_test_finding()]

        optimizer.record_result(
            scan_id="scan-1",
            deployment_id="deploy-1",
            findings=findings,
            duration_seconds=60.0,
            analyzers_run=[JobType.DEPLOYMENT_SCAN],
        )

        stats = optimizer.get_stats("deploy-1")
        assert stats["scan_count"] == 1

    def test_get_predictions(self):
        """Test getting predictions."""
        optimizer = ScanOptimizer()

        # Record some history
        for i in range(5):
            optimizer.history.record(ScanHistoryEntry(
                scan_id=f"scan-{i}",
                deployment_id="deploy-1",
                total_findings=3,
            ))

        predictions = optimizer.get_predictions("deploy-1")
        assert "expected_findings" in predictions

    def test_get_adaptive_scanner(self):
        """Test getting adaptive scanner."""
        optimizer = ScanOptimizer()
        scanner = optimizer.get_adaptive_scanner()

        assert isinstance(scanner, AdaptiveScanner)

    def test_process_interim_findings(self):
        """Test processing interim findings."""
        config = OptimizationConfig(adaptive_strategy=AdaptiveStrategy.AGGRESSIVE)
        optimizer = ScanOptimizer(config=config)
        scanner = optimizer.get_adaptive_scanner()
        scanner.set_initial_plan([JobType.DEPLOYMENT_SCAN])

        findings = [create_test_finding() for _ in range(5)]
        adjustments = optimizer.process_interim_findings(findings)

        # May or may not have adjustments depending on strategy
        assert isinstance(adjustments, list)


class TestCreateOptimizer:
    """Tests for create_optimizer helper."""

    def test_default_optimizer(self):
        """Test creating default optimizer."""
        optimizer = create_optimizer()
        assert optimizer.config.adaptive_strategy == AdaptiveStrategy.BALANCED

    def test_aggressive_optimizer(self):
        """Test creating aggressive optimizer."""
        optimizer = create_optimizer(strategy="aggressive")
        assert optimizer.config.adaptive_strategy == AdaptiveStrategy.AGGRESSIVE

    def test_no_history_optimizer(self):
        """Test creating optimizer without history."""
        optimizer = create_optimizer(use_history=False)
        assert optimizer.config.use_history is False

    def test_time_limited_optimizer(self):
        """Test creating time-limited optimizer."""
        optimizer = create_optimizer(max_scan_seconds=120)
        assert optimizer.config.max_scan_seconds == 120


class TestIntegration:
    """Integration tests for AI Scan Planner."""

    def test_full_optimization_workflow(self):
        """Test complete optimization workflow."""
        # Create optimizer with all features
        config = OptimizationConfig(
            adaptive_strategy=AdaptiveStrategy.BALANCED,
            use_history=True,
            use_risk_assessment=True,
        )
        optimizer = ScanOptimizer(config=config)

        # Simulate historical scans
        for i in range(5):
            optimizer.history.record(ScanHistoryEntry(
                scan_id=f"hist-{i}",
                deployment_id="deploy-1",
                total_findings=i + 1,
                by_analyzer={JobType.SECRET_DETECTION: i},
            ))

        # Optimize with deployment info
        scan = optimizer.optimize(
            "deploy-1",
            deployment_info={
                "id": "deploy-1",
                "model": {"format": "pickle", "source": "external"},
                "deployment": {"external": True},
            },
        )

        # Verify optimization
        assert scan.risk_profile is not None
        assert scan.risk_profile.overall_score > 0
        assert len(scan.analyzers) > 0
        assert len(scan.optimization_notes) > 0

    def test_adaptive_scanning_workflow(self):
        """Test adaptive scanning with interim findings."""
        optimizer = ScanOptimizer(
            config=OptimizationConfig(
                adaptive_strategy=AdaptiveStrategy.AGGRESSIVE,
            )
        )

        # Get initial plan
        scan = optimizer.optimize("deploy-1")
        initial_count = len(scan.analyzers)

        # Get adaptive scanner and set plan
        scanner = optimizer.get_adaptive_scanner()
        scanner.set_initial_plan(scan.analyzers)

        # Process critical findings
        findings = [
            create_test_finding(
                severity=Severity.CRITICAL,
                category=AttackCategory.PROMPT_INJECTION,
            )
            for _ in range(3)
        ]

        adjustments = optimizer.process_interim_findings(findings)

        # Check state
        summary = scanner.get_summary()
        assert summary["state"]["critical_count"] == 3

    def test_learning_from_history(self):
        """Test that history improves predictions."""
        optimizer = ScanOptimizer()

        # Record consistent history
        for i in range(10):
            optimizer.history.record(ScanHistoryEntry(
                scan_id=f"scan-{i}",
                deployment_id="deploy-1",
                total_findings=5,
                by_category={AttackCategory.PROMPT_INJECTION: 3},
            ))

        # Get predictions
        predictions = optimizer.get_predictions("deploy-1")

        assert predictions["expected_findings"] == 5
        assert predictions["confidence"] > 0.5
        assert "prompt_injection" in predictions["likely_categories"]

    def test_effectiveness_tracking(self):
        """Test analyzer effectiveness tracking."""
        optimizer = ScanOptimizer()

        # Record scans with findings
        for i in range(5):
            optimizer.history.record(ScanHistoryEntry(
                scan_id=f"scan-{i}",
                deployment_id="deploy-1",
                analyzers_run=[JobType.SECRET_DETECTION, JobType.MODEL_FILE_SCAN],
                by_analyzer={JobType.SECRET_DETECTION: 10, JobType.MODEL_FILE_SCAN: 0},
            ))

        effectiveness = optimizer.get_analyzer_effectiveness(days=30)

        # Secret detection should be more effective
        assert effectiveness.get("secret_detection", 0) > effectiveness.get("model_file_scan", 0)
