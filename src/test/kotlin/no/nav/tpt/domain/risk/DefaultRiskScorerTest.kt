package no.nav.tpt.domain.risk

import org.junit.Assert.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import kotlin.collections.find
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DefaultRiskScorerTest {

    private val riskScorer = DefaultRiskScorer()

    @Test
    fun `should apply 0_3 multiplier to suppressed vulnerabilities`() {
        val suppressedScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = true,
                epssScore = "0.9",
                suppressed = true,
                environment = null,
                buildDate = null
            )
        ).score

        val normalScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = true,
                epssScore = "0.9",
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertEquals(0.3, suppressedScore / normalScore, 0.001)
        assertTrue(suppressedScore > 0.0)
    }

    @Test
    fun `should calculate higher risk for critical vulnerability with external ingress`() {
        val criticalExternal = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        val mediumExternal = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertTrue(criticalExternal > mediumExternal)
    }

    @Test
    fun `should apply external ingress multiplier correctly`() {
        val baseScore = 100.0
        val externalMultiplier = 2.0

        val score = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertEquals(baseScore * externalMultiplier, score, 0.001)
    }

    @Test
    fun `should apply KEV multiplier correctly`() {
        val withKev = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = true,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        val withoutKev = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertEquals(1.5, withKev / withoutKev, 0.001)
    }

    @Test
    fun `should apply EPSS multiplier correctly`() {
        val highEpss = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = false,
                epssScore = "0.8",
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        val noEpss = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertTrue(highEpss > noEpss)
    }

    @Test
    fun `should multiply all factors together`() {
        val baseScore = 100.0
        val externalMultiplier = 2.0
        val kevMultiplier = 1.5
        val epssMultiplier = 1.5

        val score = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = true,
                epssScore = "0.8",
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        val expected = baseScore * externalMultiplier * kevMultiplier * epssMultiplier
        assertEquals(expected, score, 0.001)
    }

    @Test
    fun `should reduce score for internal ingress compared to external`() {
        val external = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        val internal = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertTrue(external > internal)
    }

    @Test
    fun `should reduce score for authenticated compared to external`() {
        val external = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        val authenticated = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("AUTHENTICATED"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertTrue(external > authenticated)
    }

    @Test
    fun `should not reduce score for low EPSS values`() {
        val lowEpss = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = "0.05",
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        val noEpss = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertEquals(lowEpss, noEpss)
    }

    @Test
    fun `should reduce score for no ingress`() {
        val withIngress = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        val noIngress = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = emptyList(),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertTrue(noIngress < withIngress)
    }

    @Test
    fun `should handle invalid EPSS score gracefully`() {
        val score = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = "invalid",
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertTrue(score > 0.0)
    }

    @Test
    fun `should prioritize external over internal when multiple ingress types exist`() {
        val mixed = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("INTERNAL", "EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        val externalOnly = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertEquals(externalOnly, mixed)
    }

    @Test
    fun `should apply 1_1 multiplier for prod-gcp environment`() {
        val prodScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = "prod-gcp",
                buildDate = null
            )
        ).score

        val devScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = "dev-gcp",
                buildDate = null
            )
        ).score

        assertEquals(1.1, prodScore / devScore, 0.001)
    }

    @Test
    fun `should apply 1_1 multiplier for prod-fss environment`() {
        val prodScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = "prod-fss",
                buildDate = null
            )
        ).score

        val devScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = "dev-fss",
                buildDate = null
            )
        ).score

        assertEquals(1.1, prodScore / devScore, 0.001)
    }

    @Test
    fun `should not apply multiplier for dev environments`() {
        val devGcpScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = "dev-gcp",
                buildDate = null
            )
        ).score

        val noEnvScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertEquals(devGcpScore, noEnvScore)
    }

    @Test
    fun `should not apply multiplier for null environment`() {
        val score = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        val baseScore = 70.0
        val externalMultiplier = 2.0
        val expected = baseScore * externalMultiplier

        assertEquals(expected, score, 0.001)
    }

    @Test
    fun `should apply 1_1 multiplier for old builds`() {
        val oldBuildDate = java.time.LocalDate.now().minusDays(100)

        val oldBuildScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = oldBuildDate
            )
        ).score

        val recentBuildScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = java.time.LocalDate.now().minusDays(30)
            )
        ).score

        assertEquals(1.1, oldBuildScore / recentBuildScore, 0.001)
    }

    @Test
    fun `should not apply multiplier for recent builds`() {
        val recentBuildScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = java.time.LocalDate.now().minusDays(30)
            )
        ).score

        val noBuildDateScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertEquals(recentBuildScore, noBuildDateScore)
    }

    @Test
    fun `should apply multiplier at 90 day threshold`() {
        val atThreshold = java.time.LocalDate.now().minusDays(91)

        val score = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = atThreshold
            )
        ).score

        val baseScore = 40.0
        val internalMultiplier = 1.0
        val oldBuildMultiplier = 1.1
        val expected = baseScore * internalMultiplier * oldBuildMultiplier

        assertEquals(expected, score, 0.001)
    }

    @Test
    fun `should include build age in multipliers when old`() {
        val oldBuildDate = java.time.LocalDate.now().minusDays(120)

        val result = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = oldBuildDate
            )
        ).breakdown?.factors

        assertNotNull(result)
        assertTrue(result?.find { it.name == "build_age" } != null)
        assertEquals(1.1, result.find { it.name == "build_age" }?.multiplier) }

    @Test
    fun `should not include build age in multipliers when recent`() {
        val recentBuildDate = java.time.LocalDate.now().minusDays(30)

        val result = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = recentBuildDate
            )
        ).breakdown?.factors

        assertFalse(result?.find { it.name == "old_build" } != null)
        assertFalse(result?.find { it.name == "old_build_days" } != null)
    }

    @Test
    fun `should include severity factor in breakdown with correct percentage`() {
        val result = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        )

        val breakdown = result.breakdown
        val severityFactor = breakdown?.factors?.find { it.name == "severity" }

        assertTrue(severityFactor != null, "Severity factor should be present in breakdown")
        assertEquals(70.0, severityFactor.contribution, 0.01)
        assertEquals("HIGH", severityFactor.explanation.substringAfter("(").substringBefore(")"))
        assertEquals(ImpactLevel.HIGH, severityFactor.impact)
    }

    @Test
    fun `should assign CRITICAL impact for severity base score of 100`() {
        val result = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = emptyList(),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        )

        val severityFactor = result.breakdown?.factors?.find { it.name == "severity" }
        assertTrue(severityFactor != null)
        assertEquals(ImpactLevel.CRITICAL, severityFactor.impact)
    }

    @Test
    fun `should assign HIGH impact for severity base score of 70`() {
        val result = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = emptyList(),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        )

        val severityFactor = result.breakdown?.factors?.find { it.name == "severity" }
        assertTrue(severityFactor != null)
        assertEquals(ImpactLevel.HIGH, severityFactor.impact)
        assertEquals(70.0, severityFactor.contribution, 0.01)
    }

    @Test
    fun `should assign MEDIUM impact for severity base score of 40`() {
        val result = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = emptyList(),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        )

        val severityFactor = result.breakdown?.factors?.find { it.name == "severity" }
        assertTrue(severityFactor != null)
        assertEquals(ImpactLevel.MEDIUM, severityFactor.impact)
        assertEquals(40.0, severityFactor.contribution, 0.01)
    }

    @Test
    fun `should assign LOW impact for severity base score of 20`() {
        val result = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "LOW",
                ingressTypes = emptyList(),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        )

        val severityFactor = result.breakdown?.factors?.find { it.name == "severity" }
        assertTrue(severityFactor != null)
        assertEquals(ImpactLevel.LOW, severityFactor.impact)
        assertEquals(20.0, severityFactor.contribution, 0.01)
    }

    @Test
    fun `should assign CRITICAL impact for exposure factor with 2x multiplier`() {
        val result = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        )

        val exposureFactor = result.breakdown?.factors?.find { it.name == "exposure" }
        assertEquals(ImpactLevel.CRITICAL, exposureFactor?.impact)
        assertEquals(2.0, result.breakdown?.factors?.find { it.name == "exposure" }?.multiplier)
    }

    @Test
    fun `should assign HIGH impact for KEV factor with 1_5x multiplier`() {
        val result = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = emptyList(),
                hasKevEntry = true,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        )

        val kevFactor = result.breakdown?.factors?.find { it.name == "kev" }
        assertEquals(ImpactLevel.HIGH, kevFactor?.impact)
        assertEquals(1.5, result.breakdown?.factors?.find { it.name == "kev" }?.multiplier)
    }

    @Test
    fun `should assign appropriate impact for EPSS factor based on multiplier`() {
        val highEpssResult = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = emptyList(),
                hasKevEntry = false,
                epssScore = "0.9",
                suppressed = false,
                environment = null,
                buildDate = null
            )
        )

        val epssFactor = highEpssResult.breakdown?.factors?.find { it.name == "epss" }
        assertTrue(epssFactor != null)
        assertTrue(epssFactor.impact in listOf(ImpactLevel.HIGH, ImpactLevel.CRITICAL))
    }

    @Test
    fun `should assign HIGH impact for suppression factor`() {
        val result = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = emptyList(),
                hasKevEntry = false,
                epssScore = null,
                suppressed = true,
                environment = null,
                buildDate = null
            )
        )

        val suppressionFactor = result.breakdown?.factors?.find { it.name == "suppression" }
        assertEquals(ImpactLevel.HIGH, suppressionFactor?.impact)
        assertEquals(0.3, result.breakdown?.factors?.find { it.name == "suppression" }?.multiplier)
    }

    @Test
    fun `should assign LOW impact for production environment factor`() {
        val result = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = "prod-gcp",
                buildDate = null
            )
        )

        val envFactor = result.breakdown?.factors?.find { it.name == "environment" }
        assertTrue(envFactor != null, "Environment factor should be present")
        assertEquals(ImpactLevel.LOW, envFactor.impact)
        assertEquals(1.1, result.breakdown.factors.find { it.name == "environment" }?.multiplier)
    }
}

