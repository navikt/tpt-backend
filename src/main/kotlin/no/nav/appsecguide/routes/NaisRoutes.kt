package no.nav.appsecguide.routes

import io.ktor.http.*
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.principal
import io.ktor.server.response.*
import io.ktor.server.routing.*
import no.nav.appsecguide.infrastructure.nais.toDto
import no.nav.appsecguide.plugins.TokenPrincipal
import no.nav.appsecguide.plugins.dependencies

fun Route.naisRoutes() {
    authenticate("auth-bearer") {
        get("/applications/{teamSlug}") {
            val teamSlug = call.parameters["teamSlug"] ?: run {
                call.respondBadRequest("teamSlug path parameter is required")
                return@get
            }

            try {
                val response = call.dependencies.naisApiService.getApplicationsForTeam(teamSlug)
                if (response.errors != null && response.errors.isNotEmpty()) {
                    call.respondWithGraphQLOrError(response, response.errors)
                } else {
                    call.respond(HttpStatusCode.OK, response.toDto(teamSlug))
                }
            } catch (e: Exception) {
                call.respondInternalServerError("Failed to fetch team applications", e)
            }
        }

        get("/applications/user") {
            val principal = call.principal<TokenPrincipal>()
            val email = principal?.preferredUsername

            if (email == null) {
                call.respondBadRequest("preferred_username claim not found in token")
                return@get
            }

            try {
                val response = call.dependencies.naisApiService.getApplicationsForUser(email)
                if (response.errors != null && response.errors.isNotEmpty()) {
                    call.respondWithGraphQLOrError(response, response.errors)
                } else {
                    call.respond(HttpStatusCode.OK, response.toDto())
                }
            } catch (e: Exception) {
                call.respondInternalServerError("Failed to fetch applications for user", e)
            }
        }

        get("/vulnerabilities/{teamSlug}") {
            val teamSlug = call.parameters["teamSlug"] ?: run {
                call.respondBadRequest("teamSlug path parameter is required")
                return@get
            }

            try {
                val response = call.dependencies.naisApiService.getVulnerabilitiesForTeam(teamSlug)
                if (response.errors != null && response.errors.isNotEmpty()) {
                    call.respondWithGraphQLOrError(response, response.errors)
                } else {
                    call.respond(HttpStatusCode.OK, response.toDto(teamSlug))
                }
            } catch (e: Exception) {
                call.respondInternalServerError("Failed to fetch team vulnerabilities", e)
            }
        }

        get("/vulnerabilities/user") {
            val principal = call.principal<TokenPrincipal>()
            val email = principal?.preferredUsername

            if (email == null) {
                call.respondBadRequest("preferred_username claim not found in token")
                return@get
            }

            try {
                val response = call.dependencies.naisApiService.getVulnerabilitiesForUser(email)
                if (response.errors != null && response.errors.isNotEmpty()) {
                    call.respondWithGraphQLOrError(response, response.errors)
                } else {
                    call.respond(HttpStatusCode.OK, response.toDto())
                }
            } catch (e: Exception) {
                call.respondInternalServerError("Failed to fetch vulnerabilities for user", e)
            }
        }
    }
}
