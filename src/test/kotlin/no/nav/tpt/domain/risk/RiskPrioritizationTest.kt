package no.nav.tpt.domain.risk

import no.nav.tpt.infrastructure.config.AppConfig
import java.time.LocalDate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Comparative prioritization tests for the risk scoring model.
 *
 * Each test presents two scenarios (A and B) and asserts that A ranks higher than B.
 * Tests are tied to [AppConfig] bucket thresholds and [RiskScoringConfig] defaults.
 *
 * When a config change causes a bucket to shift, the test failure message will tell you:
 * - The actual scores for both scenarios
 * - The active bucket thresholds (CRITICAL/HIGH/MEDIUM)
 * - Which bucket changed
 *
 * If you intentionally changed the scoring model or thresholds, update the expected buckets here.
 */
class RiskPrioritizationTest {

    private val scorer = DefaultRiskScorer(RiskScoringConfig())

    private val criticalThreshold = AppConfig.DEFAULT_RISK_THRESHOLD_CRITICAL
    private val highThreshold = AppConfig.DEFAULT_RISK_THRESHOLD_HIGH
    private val mediumThreshold = AppConfig.DEFAULT_RISK_THRESHOLD_MEDIUM

    private fun bucket(score: Double) = when {
        score >= criticalThreshold -> "CRITICAL"
        score >= highThreshold -> "HIGH"
        score >= mediumThreshold -> "MEDIUM"
        else -> "LOW"
    }

    private fun assertRankedHigher(scoreA: Double, labelA: String, scoreB: Double, labelB: String) {
        assertTrue(scoreA > scoreB,
            """
            |Priority ordering violated:
            |  $labelA scored $scoreA (${bucket(scoreA)})
            |  $labelB scored $scoreB (${bucket(scoreB)})
            |  Expected $labelA to score higher than $labelB.
            |  Thresholds: CRITICAL≥$criticalThreshold, HIGH≥$highThreshold, MEDIUM≥$mediumThreshold
            |  Check ExploitationEvidenceCalculator, EnvironmentCalculator, ActionabilityCalculator or scoring config.
            """.trimMargin())
    }

    private fun assertBucket(score: Double, expectedBucket: String, label: String) {
        assertEquals(expectedBucket, bucket(score),
            """
            |Bucket changed for "$label": expected $expectedBucket, got ${bucket(score)} (score=$score).
            |Thresholds: CRITICAL≥$criticalThreshold, HIGH≥$highThreshold, MEDIUM≥$mediumThreshold
            |If you intentionally changed scoring config or thresholds, update the expected bucket in this test.
            """.trimMargin())
    }

    // -----------------------------------------------------------------------
    // Scenario 1: Actively exploited & reachable & fixable should outrank
    //             theoretical PoC that nobody is using, with no attack surface
    //
    // A: CRITICAL + KEV + external + prod + patch
    //    25 + 30 + 20 + 10 + 5 = 90 → CRITICAL
    //
    // B: HIGH + PoC(EPSS 0.015, < epssLowThreshold) + no ingress + prod + no patch
    //    18 + 10 + 0 + 10 - 3 = 35 → MEDIUM
    // -----------------------------------------------------------------------
    @Test
    fun `prioritization - actively exploited reachable fixable should rank higher than theoretical poc with no attack surface`() {
        val scenarioA = scorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = true,
                epssScore = null,
                suppressed = false,
                environment = "prod-gcp",
                buildDate = null,
                hasPatchReference = true,
            )
        )
        val scenarioB = scorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = emptyList(),
                hasKevEntry = false,
                epssScore = "0.015",
                suppressed = false,
                environment = "prod-gcp",
                buildDate = null,
                hasExploitReference = true,
            )
        )
        assertRankedHigher(scenarioA.score, "CRITICAL+KEV+external+prod+patch", scenarioB.score, "HIGH+PoC(0.015)+no-ingress+prod")
        assertBucket(scenarioA.score, "CRITICAL", "CRITICAL+KEV+external+prod+patch")
        assertBucket(scenarioB.score, "MEDIUM", "HIGH+PoC(0.015)+no-ingress+prod")
    }

    // -----------------------------------------------------------------------
    // Scenario 2: PoC with high exploitation probability should rank higher
    //             than PoC with minimal exploitation probability and no exposure
    //
    // A: HIGH + PoC + EPSS 0.6 (≥ epssHighThreshold) + external + prod
    //    18 + 25 + 20 + 10 - 3 = 70 → HIGH
    //
    // B: HIGH + PoC + EPSS 0.015 (< epssLowThreshold) + no ingress + prod
    //    18 + 10 + 0 + 10 - 3 = 35 → MEDIUM
    // -----------------------------------------------------------------------
    @Test
    fun `prioritization - poc with high exploitation probability should rank higher than poc with minimal probability and no exposure`() {
        val scenarioA = scorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = "0.60",
                suppressed = false,
                environment = "prod-gcp",
                buildDate = null,
                hasExploitReference = true,
            )
        )
        val scenarioB = scorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = emptyList(),
                hasKevEntry = false,
                epssScore = "0.015",
                suppressed = false,
                environment = "prod-gcp",
                buildDate = null,
                hasExploitReference = true,
            )
        )
        assertRankedHigher(scenarioA.score, "HIGH+PoC+EPSS(0.6)+external+prod", scenarioB.score, "HIGH+PoC+EPSS(0.015)+no-ingress+prod")
        assertBucket(scenarioA.score, "HIGH", "HIGH+PoC+EPSS(0.6)+external+prod")
        assertBucket(scenarioB.score, "MEDIUM", "HIGH+PoC+EPSS(0.015)+no-ingress+prod")
    }

    // -----------------------------------------------------------------------
    // Scenario 3: Confirmed exploited & fixable should outrank high-severity
    //             theoretical with no attack surface and no fix available
    //
    // A: MEDIUM + KEV + external + prod + patch
    //    12 + 30 + 20 + 10 + 5 = 77 → CRITICAL
    //
    // B: HIGH + no exploit + no ingress + prod + no patch
    //    18 + 0 + 0 + 10 - 3 = 25 → LOW
    // -----------------------------------------------------------------------
    @Test
    fun `prioritization - confirmed exploited fixable should rank higher than high severity unfixable with no exposure`() {
        val scenarioA = scorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = true,
                epssScore = null,
                suppressed = false,
                environment = "prod-gcp",
                buildDate = null,
                hasPatchReference = true,
            )
        )
        val scenarioB = scorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = emptyList(),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = "prod-gcp",
                buildDate = null,
            )
        )
        assertRankedHigher(scenarioA.score, "MEDIUM+KEV+external+prod+patch", scenarioB.score, "HIGH+no-exploit+no-ingress+prod")
        assertBucket(scenarioA.score, "CRITICAL", "MEDIUM+KEV+external+prod+patch")
        assertBucket(scenarioB.score, "LOW", "HIGH+no-exploit+no-ingress+prod")
    }

    // -----------------------------------------------------------------------
    // Scenario 4: Same vulnerability should rank higher when it has an attack surface
    //
    // A: HIGH + PoC + low EPSS + external + prod
    //    18 + 10 + 20 + 10 - 3 = 55 → HIGH
    //
    // B: HIGH + PoC + low EPSS + no ingress + prod (identical except no external exposure)
    //    18 + 10 + 0 + 10 - 3 = 35 → MEDIUM
    // -----------------------------------------------------------------------
    @Test
    fun `prioritization - same vulnerability ranks higher when it has external attack surface`() {
        val scenarioA = scorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = "0.05",
                suppressed = false,
                environment = "prod-gcp",
                buildDate = null,
                hasExploitReference = true,
            )
        )
        val scenarioB = scorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = emptyList(),
                hasKevEntry = false,
                epssScore = "0.05",
                suppressed = false,
                environment = "prod-gcp",
                buildDate = null,
                hasExploitReference = true,
            )
        )
        assertRankedHigher(scenarioA.score, "HIGH+PoC+lowEPSS+external+prod", scenarioB.score, "HIGH+PoC+lowEPSS+no-ingress+prod")
        assertBucket(scenarioA.score, "HIGH", "HIGH+PoC+lowEPSS+external+prod")
        assertBucket(scenarioB.score, "MEDIUM", "HIGH+PoC+lowEPSS+no-ingress+prod")
    }

    // -----------------------------------------------------------------------
    // Scenario 5: Reachable and patchable should outrank same severity with
    //             no exposure, dev environment and no fix available
    //
    // A: CRITICAL + no exploit + external + prod + patch
    //    25 + 0 + 20 + 10 + 5 = 60 → HIGH
    //
    // B: CRITICAL + no exploit + no ingress + dev + no patch
    //    25 + 0 + 0 + 0 - 3 = 22 → LOW
    // -----------------------------------------------------------------------
    @Test
    fun `prioritization - reachable and patchable critical should rank higher than unreachable unfixable in dev`() {
        val scenarioA = scorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = "prod-gcp",
                buildDate = null,
                hasPatchReference = true,
            )
        )
        val scenarioB = scorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = emptyList(),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = "dev-gcp",
                buildDate = null,
            )
        )
        assertRankedHigher(scenarioA.score, "CRITICAL+no-exploit+external+prod+patch", scenarioB.score, "CRITICAL+no-exploit+no-ingress+dev")
        assertBucket(scenarioA.score, "HIGH", "CRITICAL+no-exploit+external+prod+patch")
        assertBucket(scenarioB.score, "LOW", "CRITICAL+no-exploit+no-ingress+dev")
    }

    // -----------------------------------------------------------------------
    // Scenario 6: Real exploitation probability beats inflated score from
    //             age bonuses when there is no network exposure
    //
    // A: HIGH + EPSS 0.4 (moderate) + external + prod
    //    18 + 10 + 20 + 10 - 3 = 55 → HIGH
    //
    // B: HIGH + PoC(EPSS 0.01) + no ingress + prod + old build + old CVE
    //    Without fixes: 18 + 18 + 0 + 10 + 3 + 2 = 51 → HIGH  (incorrectly same tier)
    //    With fixes:    18 + 10 + 0 + 10 + 0 - 3 = 35 → MEDIUM (correctly lower)
    // -----------------------------------------------------------------------
    @Test
    fun `prioritization - moderate real exploitation probability should rank higher than inflated score from age bonuses with no exposure`() {
        val scenarioA = scorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = "0.40",
                suppressed = false,
                environment = "prod-gcp",
                buildDate = null,
            )
        )
        val scenarioB = scorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = emptyList(),
                hasKevEntry = false,
                epssScore = "0.01",
                suppressed = false,
                environment = "prod-gcp",
                buildDate = LocalDate.now().minusDays(120),
                cveDaysOld = 400,
                hasExploitReference = true,
            )
        )
        assertRankedHigher(scenarioA.score, "HIGH+EPSS(0.4)+external+prod", scenarioB.score, "HIGH+PoC+EPSS(0.01)+no-ingress+old-build+old-CVE")
        assertBucket(scenarioA.score, "HIGH", "HIGH+EPSS(0.4)+external+prod")
        assertBucket(scenarioB.score, "MEDIUM", "HIGH+PoC+EPSS(0.01)+no-ingress+old-build+old-CVE")
    }
}
