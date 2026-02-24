package no.nav.tpt.routes

import io.ktor.server.response.*
import io.ktor.server.routing.*
import no.nav.tpt.domain.ConfigResponse
import no.nav.tpt.domain.RiskThresholds
import no.nav.tpt.plugins.dependencies

fun Route.configRoutes() {
    get("/config") {
        val appConfig = call.dependencies.appConfig
        val response = ConfigResponse(
            thresholds = RiskThresholds(
                high = appConfig.riskThresholdHigh,
                medium = appConfig.riskThresholdMedium,
                low = appConfig.riskThresholdLow
            ),
            aiEnabled = call.dependencies.remediationService != null
        )
        call.respond(response)
    }
}

