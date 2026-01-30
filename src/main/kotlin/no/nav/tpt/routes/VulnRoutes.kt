package no.nav.tpt.routes

import io.ktor.http.*
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.principal
import io.ktor.server.plugins.ratelimit.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import no.nav.tpt.plugins.TokenPrincipal
import no.nav.tpt.plugins.dependencies

fun Route.vulnRoutes() {
    authenticate("auth-bearer") {
        get("/vulnerabilities/user") {
            val principal = call.principal<TokenPrincipal>()
            val email = principal?.preferredUsername

            if (email == null) {
                call.respondBadRequest("preferred_username claim not found in token")
                return@get
            }

            try {
                val vulnService = call.dependencies.vulnService
                val response = vulnService.fetchVulnerabilitiesForUser(email)
                call.respond(HttpStatusCode.OK, response)
            } catch (e: Exception) {
                call.respondInternalServerError("Failed to fetch vulnerabilities", e)
            }
        }

        rateLimit(RateLimitName("vulnerabilities-refresh")) {
            post("/vulnerabilities/refresh") {
                val principal = call.principal<TokenPrincipal>()
                val email = principal?.preferredUsername

                if (email == null) {
                    call.respondBadRequest("preferred_username claim not found in token")
                    return@post
                }

                try {
                    val vulnerabilityTeamSyncService = call.dependencies.vulnerabilityTeamSyncService
                    val userContextService = call.dependencies.userContextService
                    
                    val userContext = userContextService.getUserContext(email)
                    
                    if (userContext.teams.isEmpty()) {
                        call.respond(HttpStatusCode.OK, mapOf(
                            "message" to "No teams to refresh",
                            "results" to emptyList<Any>()
                        ))
                        return@post
                    }
                    
                    val results = vulnerabilityTeamSyncService.syncTeams(userContext.teams)
                    
                    call.respond(HttpStatusCode.OK, mapOf(
                        "message" to "Successfully refreshed vulnerability data",
                        "results" to results.map { result ->
                            mapOf(
                                "teamSlug" to result.teamSlug,
                                "processed" to result.processed,
                                "inserted" to result.inserted,
                                "skipped" to result.skipped
                            )
                        }
                    ))
                } catch (e: Exception) {
                    call.respondInternalServerError("Failed to refresh vulnerabilities", e)
                }
            }
        }

        get("/vulnerabilities/github/user") {
            val principal = call.principal<TokenPrincipal>()
            val email = principal?.preferredUsername

            if (email == null) {
                call.respondBadRequest("preferred_username claim not found in token")
                return@get
            }

            try {
                val vulnService = call.dependencies.vulnService
                val response = vulnService.fetchGitHubVulnerabilitiesForUser(email)
                call.respond(HttpStatusCode.OK, response)
            } catch (e: Exception) {
                call.respondInternalServerError("Failed to fetch GitHub vulnerabilities", e)
            }
        }
    }
}

