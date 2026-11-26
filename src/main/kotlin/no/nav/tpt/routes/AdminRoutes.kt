package no.nav.tpt.routes

import io.ktor.http.*
import io.ktor.server.application.createRouteScopedPlugin
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.coroutines.launch
import no.nav.tpt.plugins.ForbiddenException
import no.nav.tpt.plugins.InternalServerException
import no.nav.tpt.plugins.TokenPrincipal
import no.nav.tpt.plugins.UnauthorizedException
import no.nav.tpt.plugins.dependencies
import org.slf4j.LoggerFactory

fun Route.adminRoutes() {
    val logger = LoggerFactory.getLogger("AdminRoutes")

    authenticate("auth-bearer") {
        route("/admin") {
            install(RequireAdmin)
            get("/status") {
                call.respond(HttpStatusCode.OK, mapOf("status" to "OK"))
            }
            
            get("/teams/overview") {
                val adminService = call.dependencies.adminService
                val overview = adminService.getTeamsOverview()
                call.respond(HttpStatusCode.OK, overview)
            }
            
            get("/teams/sla") {
                val adminService = call.dependencies.adminService
                val slaReport = adminService.getTeamsSlaReport()
                call.respond(HttpStatusCode.OK, slaReport)
            }

            get("/vulnerabilities/team/{teamSlug}") {
                val teamSlug = call.parameters["teamSlug"]
                    ?: throw no.nav.tpt.plugins.BadRequestException("teamSlug path parameter is required")

                try {
                    val enrichmentService = call.dependencies.vulnerabilityEnrichmentService
                    val response = enrichmentService.enrichVulnerabilitiesForTeam(teamSlug)
                    call.respond(HttpStatusCode.OK, response)
                } catch (e: Exception) {
                    throw InternalServerException("Failed to fetch vulnerabilities for team $teamSlug", e)
                }
            }

            post("/reports/refresh") {
                val syncJob = call.dependencies.vulnerabilityDataSyncJob
                val application = call.application

                application.launch {
                    try {
                        syncJob.refreshAdminReports()
                    } catch (e: Exception) {
                        logger.error("Admin report refresh failed: ${e.message}", e)
                    }
                }

                call.respond(
                    HttpStatusCode.Accepted,
                    mapOf("message" to "Admin report refresh started. Check application logs for progress.")
                )
            }

            post("/sync/trigger") {
                val syncJob = call.dependencies.vulnerabilityDataSyncJob
                val application = call.application

                application.launch {
                    try {
                        syncJob.syncAllTeams()
                    } catch (e: Exception) {
                        logger.error("Manual vulnerability sync failed: ${e.message}", e)
                    }
                }

                call.respond(
                    HttpStatusCode.Accepted,
                    mapOf("message" to "Full vulnerability sync started on leader pod. Check application logs for progress.")
                )
            }
        }
    }
}

val RequireAdmin = createRouteScopedPlugin("RequireAdmin") {
    on(AuthenticationChecked) { call ->
        val principal = call.principal<TokenPrincipal>()
            ?: throw UnauthorizedException("Mangler token")
        if (!call.dependencies.adminAuthorizationService.isAdmin(principal.groups)) {
            throw ForbiddenException("User does not have admin privileges")
        }
    }
}
