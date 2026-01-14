package no.nav.tpt.domain.risk

import no.nav.tpt.infrastructure.config.AppConfig
import org.junit.jupiter.api.Assertions.assertNotNull
import kotlin.collections.find
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DefaultRiskScorerTest {

    private val config = RiskScoringConfig()
    private val riskScorer = DefaultRiskScorer(config)

    @Test
    fun `should prioritize critical over medium severity`() {
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
    fun `should prioritize external exposure over internal`() {
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

        val internal = riskScorer.calculateRiskScore(
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

        assertTrue(external > internal)
    }

    @Test
    fun `should prioritize authenticated over internal but below external`() {
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

        val internal = riskScorer.calculateRiskScore(
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

        assertTrue(external > authenticated)
        assertTrue(authenticated > internal)
    }

    @Test
    fun `should deprioritize vulnerabilities with no ingress`() {
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
    fun `should prioritize KEV-listed vulnerabilities`() {
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

        assertTrue(withKev > withoutKev)
    }

    @Test
    fun `should prioritize high EPSS score vulnerabilities`() {
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
    fun `should not increase score for low EPSS values`() {
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
    fun `should significantly deprioritize suppressed vulnerabilities`() {
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

        assertTrue(suppressedScore < normalScore)
        assertTrue(suppressedScore > 0.0)
    }

    @Test
    fun `should prioritize production environment over dev`() {
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

        assertTrue(prodScore > devScore)
    }

    @Test
    fun `should prioritize old builds`() {
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

        assertTrue(oldBuildScore > recentBuildScore)
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
    fun `should prioritize external when multiple ingress types exist`() {
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
    fun `should include all applicable factors in breakdown`() {
        val result = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = true,
                epssScore = "0.8",
                suppressed = false,
                environment = "prod-gcp",
                buildDate = java.time.LocalDate.now().minusDays(100)
            )
        )

        val breakdown = result.breakdown
        assertNotNull(breakdown)

        val factorNames = breakdown?.factors?.map { it.name }?.toSet()
        assertTrue(factorNames?.contains("exposure") == true)
        assertTrue(factorNames?.contains("kev") == true)
        assertTrue(factorNames?.contains("epss") == true)
        assertTrue(factorNames?.contains("environment") == true)
        assertTrue(factorNames?.contains("build_age") == true)
    }

    @Test
    fun `should correctly report exposure factor in breakdown`() {
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
        assertNotNull(exposureFactor)
        assertEquals(config.externalExposureMultiplier, exposureFactor?.multiplier)
    }

    @Test
    fun `should correctly report KEV factor in breakdown`() {
        val result = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = true,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        )

        val kevFactor = result.breakdown?.factors?.find { it.name == "kev" }
        assertNotNull(kevFactor)
        assertEquals(config.kevListedMultiplier, kevFactor?.multiplier)
    }

    @Test
    fun `should correctly report suppression factor in breakdown`() {
        val result = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = true,
                environment = null,
                buildDate = null
            )
        )

        val suppressionFactor = result.breakdown?.factors?.find { it.name == "suppression" }
        assertNotNull(suppressionFactor)
        assertEquals(config.suppressedMultiplier, suppressionFactor?.multiplier)
    }

    @Test
    fun `should correctly report environment factor in breakdown`() {
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
        assertNotNull(envFactor)
        assertEquals(config.productionEnvironmentMultiplier, envFactor?.multiplier)
    }

    @Test
    fun `should score critical vulnerability with external ingress in production above highest threshold`() {
        val result = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = "prod-gcp",
                buildDate = null
            )
        )

        assertTrue(
            result.score > AppConfig.DEFAULT_RISK_THRESHOLD_HIGH,
            "Critical vulnerability with external ingress in production should score above ${AppConfig.DEFAULT_RISK_THRESHOLD_HIGH}, but got ${result.score}"
        )
    }

    @Test
    fun `should score high vulnerability with external ingress and kev above highest threshold`() {
        val result = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = true,
                epssScore = null,
                suppressed = false,
                environment = "dev-gcp",
                buildDate = null
            )
        )

        assertTrue(result.score > AppConfig.DEFAULT_RISK_THRESHOLD_HIGH,
            "High vulnerability with external ingress and KEV in dev should score above ${AppConfig.DEFAULT_RISK_THRESHOLD_HIGH}, but got ${result.score}"
        )
    }

    @Test
    fun `should score critical vulnerability with no ingress and kev below highest threshold`() {
        val result = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = emptyList(),
                hasKevEntry = true,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        )

        assertTrue(result.score < AppConfig.DEFAULT_RISK_THRESHOLD_HIGH,
            "Critical vulnerability with no ingress and KEV should score below ${AppConfig.DEFAULT_RISK_THRESHOLD_HIGH}, but got ${result.score}"
        )
    }

    @Test
    fun `should score medium vulnerability with external ingress in production and old build above low threshold`() {
        val result = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = "prod-gcp",
                buildDate = java.time.LocalDate.now().minusDays(120)
            )
        )

        assertTrue(result.score > AppConfig.DEFAULT_RISK_THRESHOLD_LOW,
            "Medium vulnerability with external ingress in production and old build should score above ${AppConfig.DEFAULT_RISK_THRESHOLD_LOW}, but got ${result.score}"
        )
    }

    @Test
    fun `should score suppressed critical vulnerability with all risk factors between medium and high threshold`() {
        val result = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = true,
                epssScore = "0.9",
                suppressed = true,
                environment = "prod-gcp",
                buildDate = java.time.LocalDate.now().minusDays(120)
            )
        )

        assertTrue(result.score > AppConfig.DEFAULT_RISK_THRESHOLD_MEDIUM && result.score < AppConfig.DEFAULT_RISK_THRESHOLD_HIGH,
            "Suppressed critical vulnerability should score below ${AppConfig.DEFAULT_RISK_THRESHOLD_MEDIUM} regardless of other factors, but got ${result.score}"
        )
    }
}

