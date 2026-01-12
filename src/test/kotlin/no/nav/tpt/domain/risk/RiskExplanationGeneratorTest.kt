package no.nav.tpt.domain.risk

import no.nav.tpt.domain.risk.factors.*
import kotlin.test.Test
import kotlin.test.assertNotEquals

class RiskExplanationGeneratorTest {

    private val config = RiskScoringConfig()
    private val generator = RiskExplanationGenerator(config)

    private val factorCalculators: List<FactorCalculator> = listOf(
        ExposureFactorCalculator(config),
        KevFactorCalculator(config),
        EpssFactorCalculator(config),
        SuppressionFactorCalculator(config),
        EnvironmentFactorCalculator(config),
        BuildAgeFactorCalculator(config),
        ExploitReferenceFactorCalculator(config),
        PatchAvailableFactorCalculator(config)
    )

    @Test
    fun `should have explanation for each risk factor`() {
        val context = VulnerabilityRiskContext(
            severity = "HIGH",
            ingressTypes = listOf("EXTERNAL"),
            hasKevEntry = true,
            epssScore = "0.5",
            suppressed = true,
            environment = "prod",
            buildDate = java.time.LocalDate.now().minusDays(100),
            hasExploitReference = true,
            hasPatchReference = true,
            cveDaysOld = 365
        )

        val factors = factorCalculators.map { it.calculate(context) }
        val breakdown = generator.generateBreakdown("HIGH", 70.0, factors, 100.0)

        val factorNames = factorCalculators.map { it.calculate(context).name }.toSet()

        factorNames.forEach { name ->
            val factor = factors.first { it.name == name }
            if (factor.value != 1.0) {
                val explanation = breakdown.factors.firstOrNull { it.name == name }
                assertNotEquals(
                    name,
                    explanation?.explanation,
                    "Factor '$name' should have a proper explanation, not just the factor name"
                )
            }
        }
    }
}

