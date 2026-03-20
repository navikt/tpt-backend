package no.nav.tpt.domain.risk.factors

import no.nav.tpt.domain.risk.RiskScoringConfig
import no.nav.tpt.domain.risk.VulnerabilityRiskContext
import kotlin.test.Test
import kotlin.test.assertEquals

class ActionabilityCalculatorTest {

    private val config = RiskScoringConfig()
    private val calculator = ActionabilityCalculator(config)

    private fun context(
        hasPatchReference: Boolean = false,
        hasRansomwareCampaignUse: Boolean = false,
        nvdVulnStatus: String? = "Analyzed",
    ) = VulnerabilityRiskContext(
        severity = "HIGH", ingressTypes = emptyList(),
        hasKevEntry = false, epssScore = null, suppressed = false,
        environment = null, buildDate = null,
        hasPatchReference = hasPatchReference,
        hasRansomwareCampaignUse = hasRansomwareCampaignUse,
        nvdVulnStatus = nvdVulnStatus,
    )

    @Test
    fun `should return 5 points when patch is available`() {
        val result = calculator.calculate(context(hasPatchReference = true))
        assertEquals(config.actionabilityPatchAvailablePoints, result.points)
    }

    @Test
    fun `should return 5 points when ransomware campaign use is known`() {
        val result = calculator.calculate(context(hasRansomwareCampaignUse = true))
        assertEquals(config.actionabilityRansomwarePoints, result.points)
    }

    @Test
    fun `should return 10 points when both patch and ransomware are present`() {
        val result = calculator.calculate(context(hasPatchReference = true, hasRansomwareCampaignUse = true))
        assertEquals(
            config.actionabilityPatchAvailablePoints + config.actionabilityRansomwarePoints,
            result.points
        )
    }

    @Test
    fun `should return penalty points when NVD is analyzed and neither patch nor ransomware`() {
        val result = calculator.calculate(context(nvdVulnStatus = "Analyzed"))
        assertEquals(config.actionabilityNoPatchPenalty, result.points)
    }

    @Test
    fun `should return penalty points when NVD is modified and neither patch nor ransomware`() {
        val result = calculator.calculate(context(nvdVulnStatus = "Modified"))
        assertEquals(config.actionabilityNoPatchPenalty, result.points)
    }

    @Test
    fun `should not penalize when NVD analysis is pending`() {
        val result = calculator.calculate(context(nvdVulnStatus = "Awaiting Analysis"))
        assertEquals(0, result.points)
    }

    @Test
    fun `should not penalize when NVD status is null`() {
        val result = calculator.calculate(context(nvdVulnStatus = null))
        assertEquals(0, result.points)
    }

    @Test
    fun `should have actionability as category name`() {
        assertEquals("actionability", calculator.categoryName)
    }

    @Test
    fun `should have 10 as max points`() {
        assertEquals(10, calculator.maxPoints)
    }
}
