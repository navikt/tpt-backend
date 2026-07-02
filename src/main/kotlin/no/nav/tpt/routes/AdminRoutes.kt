package no.nav.tpt.routes

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.coroutines.launch
import no.nav.tpt.plugins.ForbiddenException
import no.nav.tpt.plugins.InternalServerException
import no.nav.tpt.plugins.TokenPrincipal
import no.nav.tpt.plugins.dependencies
import org.slf4j.LoggerFactory

fun Route.adminRoutes() {
    val logger = LoggerFactory.getLogger("AdminRoutes")

    authenticate("auth-bearer") {
        route("/admin") {
            get("/status") {
                val principal = call.principal<TokenPrincipal>()!!
                val adminAuthService = call.dependencies.adminAuthorizationService
                
                if (!adminAuthService.isAdmin(principal.groups)) {
                    throw ForbiddenException("User does not have admin privileges")
                }
                
                call.respond(HttpStatusCode.OK, mapOf("status" to "OK"))
            }
            
            get("/teams/overview") {
                val principal = call.principal<TokenPrincipal>()!!
                val adminAuthService = call.dependencies.adminAuthorizationService
                
                if (!adminAuthService.isAdmin(principal.groups)) {
                    throw ForbiddenException("User does not have admin privileges")
                }
                
                try {
                    val adminService = call.dependencies.adminService
                    val overview = adminService.getTeamsOverview()
                    call.respond(HttpStatusCode.OK, overview)
                } catch (e: Exception) {
                    throw InternalServerException("Failed to fetch teams overview", e)
                }
            }
            
            get("/teams/sla") {
                val principal = call.principal<TokenPrincipal>()!!
                val adminAuthService = call.dependencies.adminAuthorizationService
                
                if (!adminAuthService.isAdmin(principal.groups)) {
                    throw ForbiddenException("User does not have admin privileges")
                }
                
                try {
                    val adminService = call.dependencies.adminService
                    val slaReport = adminService.getTeamsSlaReport()
                    call.respond(HttpStatusCode.OK, slaReport)
                } catch (e: Exception) {
                    throw InternalServerException("Failed to fetch teams SLA report", e)
                }
            }

            get("/vulnerabilities/team/{teamSlug}") {
                val principal = call.principal<TokenPrincipal>()!!
                val adminAuthService = call.dependencies.adminAuthorizationService

                if (!adminAuthService.isAdmin(principal.groups)) {
                    throw ForbiddenException("User does not have admin privileges")
                }

                val teamSlug = call.parameters["teamSlug"]
                    ?: throw no.nav.tpt.plugins.BadRequestException("teamSlug path parameter is required")

                try {
                    val vulnService = call.dependencies.vulnService
                    val response = vulnService.fetchVulnerabilitiesForTeam(teamSlug)
                    call.respond(HttpStatusCode.OK, response)
                } catch (e: Exception) {
                    throw InternalServerException("Failed to fetch vulnerabilities for team $teamSlug", e)
                }
            }

            get("/gcve/comparison") {
                val principal = call.principal<TokenPrincipal>()!!
                val adminAuthService = call.dependencies.adminAuthorizationService

                if (!adminAuthService.isAdmin(principal.groups)) {
                    throw ForbiddenException("User does not have admin privileges")
                }

                try {
                    val comparisonService = call.dependencies.gcveComparisonService
                    val report = comparisonService.compareDataCoverage()
                    call.respond(HttpStatusCode.OK, report)
                } catch (e: Exception) {
                    throw InternalServerException("Failed to generate GCVE comparison report", e)
                }
            }

            post("/vulnrichment/backfill-ssvc") {
                val principal = call.principal<TokenPrincipal>()!!
                val adminAuthService = call.dependencies.adminAuthorizationService

                if (!adminAuthService.isAdmin(principal.groups)) {
                    throw ForbiddenException("User does not have admin privileges")
                }

                val ssvcBackfillService = call.dependencies.ssvcBackfillService
                val application = call.application

                application.launch {
                    try {
                        ssvcBackfillService.run()
                    } catch (e: Exception) {
                        logger.error("SSVC backfill failed: ${e.message}", e)
                    }
                }

                call.respond(
                    HttpStatusCode.Accepted,
                    mapOf("message" to "SSVC backfill started. Check application logs for progress and summary.")
                )
            }
        }
    }
}
