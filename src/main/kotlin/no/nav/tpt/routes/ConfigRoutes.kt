package no.nav.tpt.routes

import io.ktor.server.response.*
import io.ktor.server.routing.*
import no.nav.tpt.domain.ConfigResponse
import no.nav.tpt.domain.RiskScoringCategories
import no.nav.tpt.domain.RiskThresholds
import no.nav.tpt.domain.risk.RiskScoringConfig
import no.nav.tpt.plugins.dependencies

private val defaultScoringConfig = RiskScoringConfig()

fun Route.configRoutes() {
    get("/config") {
        val appConfig = call.dependencies.appConfig
        val response = ConfigResponse(
            thresholds = RiskThresholds(
                high = appConfig.riskThresholdHigh,
                medium = appConfig.riskThresholdMedium,
                low = appConfig.riskThresholdLow
            ),
            scoring = RiskScoringCategories(
                severityMax = defaultScoringConfig.severityCriticalPoints,
                exploitationMax = defaultScoringConfig.exploitationActivePoints,
                exposureMax = defaultScoringConfig.exposureExternalPoints,
                environmentMax = defaultScoringConfig.environmentProductionPoints +
                        defaultScoringConfig.environmentOldBuildBonus +
                        defaultScoringConfig.environmentChronicCveBonus,
                actionabilityMax = defaultScoringConfig.actionabilityPatchAvailablePoints +
                        defaultScoringConfig.actionabilityRansomwarePoints,
            ),
            aiEnabled = call.dependencies.remediationService != null
        )
        call.respond(response)
    }
}

