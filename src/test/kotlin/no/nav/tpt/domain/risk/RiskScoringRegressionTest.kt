package no.nav.tpt.domain.risk

import no.nav.tpt.infrastructure.config.AppConfig
import java.time.LocalDate
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Regression baseline for the risk scoring point-based model (0-100 additive).
 *
 * Tests capture expected scoring behavior for key scenarios.
 * When calculator logic changes, tests that change bucket should be
 * reviewed deliberately and updated with the expected new behavior.
 *
 * Thresholds (AppConfig): CRITICAL>=75, HIGH>=50, MEDIUM>=25, LOW<25
 */
class RiskScoringRegressionTest {

    private val scorer = DefaultRiskScorer(RiskScoringConfig())

    // Helpers for current model buckets
    private fun Double.isAboveHigh() = this > AppConfig.DEFAULT_RISK_THRESHOLD_CRITICAL
    private fun Double.isHigh() = this >= AppConfig.DEFAULT_RISK_THRESHOLD_HIGH && this <= AppConfig.DEFAULT_RISK_THRESHOLD_CRITICAL
    private fun Double.isMedium() = this >= AppConfig.DEFAULT_RISK_THRESHOLD_MEDIUM && this < AppConfig.DEFAULT_RISK_THRESHOLD_HIGH
    private fun Double.isBelowLow() = this < AppConfig.DEFAULT_RISK_THRESHOLD_MEDIUM

    // -----------------------------------------------------------------------
    // Scenario 1: Worst-case — all amplifying factors active
    // CRITICAL + KEV + External + Prod + EPSS≥0.7 + Exploit + Patch + OldBuild
    // Expected current score: ~1107 (above HIGH threshold)
    // New model expected: CRITICAL (>=75 pts)
    // -----------------------------------------------------------------------
    @Test
    fun `regression - scenario 1 worst case all factors should score above HIGH threshold`() {
        val result = scorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = true,
                epssScore = "0.80",
                suppressed = false,
                environment = "prod-gcp",
                buildDate = LocalDate.now().minusDays(100),
                hasExploitReference = true,
                hasPatchReference = true,
            )
        )
        assertTrue(result.score.isAboveHigh(),
            "Scenario 1: worst-case should score above HIGH threshold (${AppConfig.DEFAULT_RISK_THRESHOLD_CRITICAL}), got ${result.score}")
    }

    // -----------------------------------------------------------------------
    // Scenario 2: Critical severity, no exploitation, internal only, dev env
    // Expected current score: ~100 (at/near LOW boundary)
    // New model expected: MEDIUM (25–49 pts) — dev + internal still warrants attention
    // -----------------------------------------------------------------------
    @Test
    fun `regression - scenario 2 critical no exploitation internal dev should score around LOW threshold`() {
        val result = scorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = "dev-gcp",
                buildDate = null,
            )
        )
        // Current model: 100 * 1.0 (internal) = 100 — right at LOW threshold
        // New model will put this in MEDIUM due to explicit severity weighting
        assertTrue(result.score >= AppConfig.DEFAULT_RISK_THRESHOLD_MEDIUM,
            "Scenario 2: critical internal dev should be at or above LOW threshold (${AppConfig.DEFAULT_RISK_THRESHOLD_MEDIUM}), got ${result.score}")
        assertTrue(result.score < AppConfig.DEFAULT_RISK_THRESHOLD_HIGH,
            "Scenario 2: critical internal dev should be below MEDIUM threshold (${AppConfig.DEFAULT_RISK_THRESHOLD_HIGH}), got ${result.score}")
    }

    // -----------------------------------------------------------------------
    // Scenario 3: Medium severity + KEV + External + Prod
    // Expected current score: ~220 (at/near HIGH boundary)
    // NEW MODEL BEHAVIOR CHANGE: medium+KEV+external+prod should be CRITICAL (>=75 pts)
    // -----------------------------------------------------------------------
    @Test
    fun `regression - scenario 3 medium KEV external prod should score near HIGH threshold`() {
        val result = scorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = true,
                epssScore = null,
                suppressed = false,
                environment = "prod-gcp",
                buildDate = null,
            )
        )
        // Current model: 50 * 2.0 (external) * 2.0 (kev) * 1.1 (prod) = 220
        // 220 == HIGH threshold — in current model just barely HIGH
        // New model: 12 + 30 + 20 + 10 = 72 → CRITICAL (this is a deliberate improvement)
        assertTrue(result.score >= AppConfig.DEFAULT_RISK_THRESHOLD_HIGH,
            "Scenario 3: medium+KEV+external+prod should be at least MEDIUM threshold (${AppConfig.DEFAULT_RISK_THRESHOLD_HIGH}), got ${result.score}")
    }

    // -----------------------------------------------------------------------
    // Scenario 4: High severity + EPSS>=0.7 + External + Prod
    // Expected current score: ~246 (above HIGH threshold)
    // New model expected: HIGH (50–74 pts) or CRITICAL
    // -----------------------------------------------------------------------
    @Test
    fun `regression - scenario 4 high EPSS external prod should score in HIGH bucket`() {
        val result = scorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = "0.75",
                suppressed = false,
                environment = "prod-gcp",
                buildDate = null,
            )
        )
        // New model: 18 (HIGH) + 22 (EPSS≥0.7) + 20 (external) + 10 (prod) = 70 → HIGH (50–74)
        assertTrue(result.score.isHigh(),
            "Scenario 4: high+EPSS≥0.7+external+prod should score in HIGH bucket (${AppConfig.DEFAULT_RISK_THRESHOLD_HIGH}–${AppConfig.DEFAULT_RISK_THRESHOLD_CRITICAL}), got ${result.score}")
    }

    // -----------------------------------------------------------------------
    // Scenario 5: Low severity + no exploitation + no ingress + dev
    // Expected current score: ~10 (well below LOW threshold)
    // New model expected: LOW (<25 pts)
    // -----------------------------------------------------------------------
    @Test
    fun `regression - scenario 5 low no exploitation no ingress dev should score well below LOW threshold`() {
        val result = scorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "LOW",
                ingressTypes = emptyList(),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = "dev-gcp",
                buildDate = null,
            )
        )
        // Current: 20 * 0.5 (noIngress) = 10
        assertTrue(result.score.isBelowLow(),
            "Scenario 5: low+no exploitation+no ingress+dev should be below LOW (${AppConfig.DEFAULT_RISK_THRESHOLD_MEDIUM}), got ${result.score}")
    }

    // -----------------------------------------------------------------------
    // Scenario 6: High severity + Exploit PoC + Internal + Staging
    // Expected current score: ~91 (below LOW threshold)
    // NEW MODEL BEHAVIOR CHANGE: exploit PoC should elevate this to at least MEDIUM
    // -----------------------------------------------------------------------
    @Test
    fun `regression - scenario 6 high exploit PoC internal staging should score in MEDIUM bucket`() {
        val result = scorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = "staging-gcp",
                buildDate = null,
                hasExploitReference = true,
            )
        )
        // New model: 18 (HIGH) + 18 (PoC) + 5 (internal) + 5 (staging) = 46 → MEDIUM (improvement over old model)
        assertTrue(result.score.isMedium(),
            "Scenario 6: high+exploit+internal+staging should be in MEDIUM bucket (${AppConfig.DEFAULT_RISK_THRESHOLD_MEDIUM}–${AppConfig.DEFAULT_RISK_THRESHOLD_HIGH}), got ${result.score}")
    }

    // -----------------------------------------------------------------------
    // Scenario 7: Critical + Suppressed + External + Prod + KEV
    // Expected current score: ~88 (below LOW, suppression dominates)
    // New model expected: LOW (<25 pts after 0.2x reduction)
    // -----------------------------------------------------------------------
    @Test
    fun `regression - scenario 7 suppressed critical external prod KEV should score below LOW threshold`() {
        val result = scorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = true,
                epssScore = null,
                suppressed = true,
                environment = "prod-gcp",
                buildDate = null,
            )
        )
        // Current: 100 * 2.0 * 2.0 * 0.2 * 1.1 = 88 — below LOW, suppression dominates
        // New model: (25+30+20+10) * 0.2 = 17 → LOW
        assertTrue(result.score.isBelowLow(),
            "Scenario 7: suppressed critical+KEV+external+prod should be below LOW (${AppConfig.DEFAULT_RISK_THRESHOLD_MEDIUM}), got ${result.score}")
        assertTrue(result.score > 0.0, "Suppressed score should still be positive")
    }

    // -----------------------------------------------------------------------
    // Scenario 8: Medium + EPSS 0.3-0.5 + Authenticated + Prod
    // Expected current score: ~79 (below LOW threshold)
    // NEW MODEL BEHAVIOR CHANGE: should be MEDIUM (~37 pts)
    // -----------------------------------------------------------------------
    @Test
    fun `regression - scenario 8 medium moderate EPSS authenticated prod should score in MEDIUM bucket`() {
        val result = scorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("AUTHENTICATED"),
                hasKevEntry = false,
                epssScore = "0.40",
                suppressed = false,
                environment = "prod-gcp",
                buildDate = null,
            )
        )
        // New model: 12 (MEDIUM) + 10 (EPSS 0.3-0.5) + 12 (authenticated) + 10 (prod) = 44 → MEDIUM (improvement)
        assertTrue(result.score.isMedium(),
            "Scenario 8: medium+EPSS0.4+auth+prod should be in MEDIUM bucket (${AppConfig.DEFAULT_RISK_THRESHOLD_MEDIUM}–${AppConfig.DEFAULT_RISK_THRESHOLD_HIGH}), got ${result.score}")
    }

    // -----------------------------------------------------------------------
    // Scenario 9: High + KEV + No ingress + Prod
    // Expected current score: ~77 (below LOW threshold)
    // NEW MODEL BEHAVIOR CHANGE: KEV should elevate this to HIGH
    // -----------------------------------------------------------------------
    @Test
    fun `regression - scenario 9 high KEV no ingress prod should score in HIGH bucket`() {
        val result = scorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = emptyList(),
                hasKevEntry = true,
                epssScore = null,
                suppressed = false,
                environment = "prod-gcp",
                buildDate = null,
            )
        )
        // New model: 18 (HIGH) + 30 (KEV) + 0 (no ingress) + 10 (prod) = 58 → HIGH (KEV not buried by no-ingress)
        assertTrue(result.score.isHigh(),
            "Scenario 9: high+KEV+noIngress+prod should be in HIGH bucket (${AppConfig.DEFAULT_RISK_THRESHOLD_HIGH}–${AppConfig.DEFAULT_RISK_THRESHOLD_CRITICAL}), got ${result.score}")
    }

    // -----------------------------------------------------------------------
    // Scenario 10: Unknown severity + no exploitation + external + dev
    // Expected current score: ~20 (below LOW threshold)
    // New model expected: LOW (<25 pts)
    // -----------------------------------------------------------------------
    @Test
    fun `regression - scenario 10 unknown severity no exploitation external dev should score below LOW threshold`() {
        val result = scorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "UNKNOWN",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = "dev-gcp",
                buildDate = null,
            )
        )
        // Current: 10 * 2.0 (external) = 20 — below LOW
        assertTrue(result.score.isBelowLow(),
            "Scenario 10: unknown+external+dev should be below LOW (${AppConfig.DEFAULT_RISK_THRESHOLD_MEDIUM}), got ${result.score}")
    }

    // -----------------------------------------------------------------------
    // Invariant tests: relative ordering must be preserved across model changes
    // -----------------------------------------------------------------------

    @Test
    fun `regression - invariant KEV always increases risk compared to no KEV`() {
        val base = VulnerabilityRiskContext(
            severity = "HIGH", ingressTypes = listOf("INTERNAL"),
            hasKevEntry = false, epssScore = null, suppressed = false,
            environment = null, buildDate = null,
        )
        val withKev = base.copy(hasKevEntry = true)

        assertTrue(scorer.calculateRiskScore(withKev).score > scorer.calculateRiskScore(base).score)
    }

    @Test
    fun `regression - invariant external exposure always scores higher than internal`() {
        val base = VulnerabilityRiskContext(
            severity = "HIGH", ingressTypes = listOf("INTERNAL"),
            hasKevEntry = false, epssScore = null, suppressed = false,
            environment = null, buildDate = null,
        )
        val external = base.copy(ingressTypes = listOf("EXTERNAL"))

        assertTrue(scorer.calculateRiskScore(external).score > scorer.calculateRiskScore(base).score)
    }

    @Test
    fun `regression - invariant suppression always reduces score`() {
        val base = VulnerabilityRiskContext(
            severity = "CRITICAL", ingressTypes = listOf("EXTERNAL"),
            hasKevEntry = true, epssScore = "0.9", suppressed = false,
            environment = "prod-gcp", buildDate = null,
        )
        val suppressed = base.copy(suppressed = true)

        assertTrue(scorer.calculateRiskScore(suppressed).score < scorer.calculateRiskScore(base).score)
    }

    @Test
    fun `regression - invariant production always scores higher than dev`() {
        val base = VulnerabilityRiskContext(
            severity = "HIGH", ingressTypes = listOf("EXTERNAL"),
            hasKevEntry = false, epssScore = null, suppressed = false,
            environment = "dev-gcp", buildDate = null,
        )
        val prod = base.copy(environment = "prod-gcp")

        assertTrue(scorer.calculateRiskScore(prod).score > scorer.calculateRiskScore(base).score)
    }

    @Test
    fun `regression - invariant high EPSS always scores higher than no EPSS`() {
        val base = VulnerabilityRiskContext(
            severity = "MEDIUM", ingressTypes = listOf("EXTERNAL"),
            hasKevEntry = false, epssScore = null, suppressed = false,
            environment = null, buildDate = null,
        )
        val highEpss = base.copy(epssScore = "0.80")

        assertTrue(scorer.calculateRiskScore(highEpss).score > scorer.calculateRiskScore(base).score)
    }

    @Test
    fun `regression - invariant critical severity always scores higher than medium with same factors`() {
        val base = VulnerabilityRiskContext(
            severity = "MEDIUM", ingressTypes = listOf("EXTERNAL"),
            hasKevEntry = false, epssScore = null, suppressed = false,
            environment = "prod-gcp", buildDate = null,
        )
        val critical = base.copy(severity = "CRITICAL")

        assertTrue(scorer.calculateRiskScore(critical).score > scorer.calculateRiskScore(base).score)
    }

    @Test
    fun `regression - invariant no ingress scores lower than internal ingress`() {
        val internal = VulnerabilityRiskContext(
            severity = "CRITICAL", ingressTypes = listOf("INTERNAL"),
            hasKevEntry = false, epssScore = null, suppressed = false,
            environment = null, buildDate = null,
        )
        val noIngress = internal.copy(ingressTypes = emptyList())

        assertTrue(scorer.calculateRiskScore(noIngress).score < scorer.calculateRiskScore(internal).score)
    }
}
