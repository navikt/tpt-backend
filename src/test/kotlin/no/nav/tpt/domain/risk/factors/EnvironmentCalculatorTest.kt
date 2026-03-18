package no.nav.tpt.domain.risk.factors

import no.nav.tpt.domain.risk.RiskScoringConfig
import no.nav.tpt.domain.risk.VulnerabilityRiskContext
import java.time.LocalDate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class EnvironmentCalculatorTest {

    private val config = RiskScoringConfig()
    private val calculator = EnvironmentCalculator(config)

    private fun context(
        environment: String? = null,
        buildDate: LocalDate? = null,
        cveDaysOld: Long? = null,
    ) = VulnerabilityRiskContext(
        severity = "HIGH", ingressTypes = emptyList(),
        hasKevEntry = false, epssScore = null, suppressed = false,
        environment = environment, buildDate = buildDate, cveDaysOld = cveDaysOld,
    )

    @Test
    fun `should return 10 points for production environment`() {
        val result = calculator.calculate(context(environment = "prod-gcp"))
        assertEquals(config.environmentProductionPoints, result.points)
    }

    @Test
    fun `should return 10 points for any environment starting with prod`() {
        assertEquals(config.environmentProductionPoints, calculator.calculate(context("prod-aws")).points)
        assertEquals(config.environmentProductionPoints, calculator.calculate(context("prod-onprem")).points)
    }

    @Test
    fun `should return 10 points for prod environment without suffix`() {
        assertEquals(config.environmentProductionPoints, calculator.calculate(context("prod")).points)
    }

    @Test
    fun `should return 10 points for production environment name`() {
        assertEquals(config.environmentProductionPoints, calculator.calculate(context("production")).points)
    }

    @Test
    fun `should return 5 points for staging environment`() {
        val result = calculator.calculate(context(environment = "staging-gcp"))
        assertEquals(config.environmentStagingPoints, result.points)
    }

    @Test
    fun `should return 0 points for dev environment`() {
        val result = calculator.calculate(context(environment = "dev-gcp"))
        assertEquals(config.environmentDevelopmentPoints, result.points)
    }

    @Test
    fun `should return 0 points for null environment`() {
        val result = calculator.calculate(context(environment = null))
        assertEquals(config.environmentDevelopmentPoints, result.points)
    }

    @Test
    fun `should add 3 bonus points for build older than threshold`() {
        val oldBuildDate = LocalDate.now().minusDays(config.environmentOldBuildThresholdDays + 10)
        val result = calculator.calculate(context(environment = "prod-gcp", buildDate = oldBuildDate))
        assertEquals(config.environmentProductionPoints + config.environmentOldBuildBonus, result.points)
    }

    @Test
    fun `should not add build bonus for recent build`() {
        val recentBuildDate = LocalDate.now().minusDays(30)
        val result = calculator.calculate(context(environment = "prod-gcp", buildDate = recentBuildDate))
        assertEquals(config.environmentProductionPoints, result.points)
    }

    @Test
    fun `should not add build bonus for null build date`() {
        val result = calculator.calculate(context(environment = "prod-gcp", buildDate = null))
        assertEquals(config.environmentProductionPoints, result.points)
    }

    @Test
    fun `should add 2 bonus points for CVE older than 365 days`() {
        val result = calculator.calculate(context(
            environment = "prod-gcp",
            cveDaysOld = config.environmentChronicCveThresholdDays + 10
        ))
        assertEquals(config.environmentProductionPoints + config.environmentChronicCveBonus, result.points)
    }

    @Test
    fun `should not add CVE age bonus for recent CVE`() {
        val result = calculator.calculate(context(environment = "prod-gcp", cveDaysOld = 100L))
        assertEquals(config.environmentProductionPoints, result.points)
    }

    @Test
    fun `should accumulate both build age and CVE age bonuses`() {
        val oldBuildDate = LocalDate.now().minusDays(config.environmentOldBuildThresholdDays + 10)
        val result = calculator.calculate(context(
            environment = "prod-gcp",
            buildDate = oldBuildDate,
            cveDaysOld = config.environmentChronicCveThresholdDays + 10
        ))
        assertEquals(
            config.environmentProductionPoints + config.environmentOldBuildBonus + config.environmentChronicCveBonus,
            result.points
        )
    }

    @Test
    fun `should have environment as category name`() {
        assertEquals("environment", calculator.categoryName)
    }

    @Test
    fun `should have 15 as max points`() {
        assertEquals(15, calculator.maxPoints)
    }

    @Test
    fun `production scores higher than dev`() {
        val prodPoints = calculator.calculate(context("prod-gcp")).points
        val devPoints = calculator.calculate(context("dev-gcp")).points
        assertTrue(prodPoints > devPoints)
    }
}
