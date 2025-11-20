package no.nav.appsecguide.routes

import io.ktor.http.*
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.principal
import io.ktor.server.response.*
import io.ktor.server.routing.*
import no.nav.appsecguide.domain.ProblemDetail
import no.nav.appsecguide.plugins.TokenPrincipal
import no.nav.appsecguide.plugins.dependencies

fun Route.naisRoutes() {
    authenticate("auth-bearer") {
        get("/nais/teams/{teamSlug}/ingresses") {
            val teamSlug = call.parameters["teamSlug"] ?: run {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ProblemDetail(
                        type = "about:blank",
                        title = "Bad Request",
                        status = HttpStatusCode.BadRequest.value,
                        detail = "teamSlug path parameter is required",
                        instance = call.request.local.uri
                    )
                )
                return@get
            }

            try {
                val response = call.dependencies.naisApiService.getTeamIngressTypes(teamSlug)

                if (response.errors != null && response.errors.isNotEmpty()) {
                    call.respond(
                        HttpStatusCode.BadGateway,
                        ProblemDetail(
                            type = "about:blank",
                            title = "GraphQL Error",
                            status = HttpStatusCode.BadGateway.value,
                            detail = response.errors.joinToString("; ") { it.message },
                            instance = call.request.local.uri
                        )
                    )
                    return@get
                }

                call.respond(HttpStatusCode.OK, response)
            } catch (e: Exception) {
                call.respond(
                    HttpStatusCode.InternalServerError,
                    ProblemDetail(
                        type = "about:blank",
                        title = "Internal Server Error",
                        status = HttpStatusCode.InternalServerError.value,
                        detail = "Failed to fetch team ingresses: ${e.message}",
                        instance = call.request.local.uri
                    )
                )
            }
        }

        get("/nais/applications/user") {
            val principal = call.principal<TokenPrincipal>()
            val email = principal?.preferredUsername

            if (email == null) {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ProblemDetail(
                        type = "about:blank",
                        title = "Bad Request",
                        status = HttpStatusCode.BadRequest.value,
                        detail = "preferred_username claim not found in token",
                        instance = call.request.local.uri
                    )
                )
                return@get
            }

            try {
                val response = call.dependencies.naisApiService.getApplicationsForUser(email)

                if (response.errors != null && response.errors.isNotEmpty()) {
                    call.respond(
                        HttpStatusCode.BadGateway,
                        ProblemDetail(
                            type = "about:blank",
                            title = "GraphQL Error",
                            status = HttpStatusCode.BadGateway.value,
                            detail = response.errors.joinToString("; ") { it.message },
                            instance = call.request.local.uri
                        )
                    )
                    return@get
                }

                call.respond(HttpStatusCode.OK, response)
            } catch (e: Exception) {
                call.respond(
                    HttpStatusCode.InternalServerError,
                    ProblemDetail(
                        type = "about:blank",
                        title = "Internal Server Error",
                        status = HttpStatusCode.InternalServerError.value,
                        detail = "Failed to fetch applications for user: ${e.message}",
                        instance = call.request.local.uri
                    )
                )
            }
        }
    }
}

