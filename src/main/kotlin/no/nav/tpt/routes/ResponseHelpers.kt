package no.nav.tpt.routes

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import no.nav.tpt.domain.ProblemDetail
import org.slf4j.LoggerFactory

private val logger = LoggerFactory.getLogger("no.nav.tpt.routes.ResponseHelpers")

suspend fun ApplicationCall.respondBadRequest(detail: String) {
    respond(
        HttpStatusCode.BadRequest,
        ProblemDetail(
            type = "about:blank",
            title = "Bad Request",
            status = HttpStatusCode.BadRequest.value,
            detail = detail,
            instance = request.local.uri
        )
    )
}

suspend fun ApplicationCall.respondInternalServerError(errorContext: String, exception: Exception) {
    logger.error("$errorContext for request ${request.local.method.value} ${request.local.uri}", exception)
    respond(
        HttpStatusCode.InternalServerError,
        ProblemDetail(
            type = "about:blank",
            title = "Internal Server Error",
            status = HttpStatusCode.InternalServerError.value,
            detail = "$errorContext: ${exception.message}",
            instance = request.local.uri
        )
    )
}

suspend fun ApplicationCall.respondUnauthorized(detail: String) {
    respond(
        HttpStatusCode.Unauthorized,
        ProblemDetail(
            type = "about:blank",
            title = "Unauthorized",
            status = HttpStatusCode.Unauthorized.value,
            detail = detail,
            instance = request.local.uri
        )
    )
}

suspend fun ApplicationCall.respondForbidden(detail: String) {
    respond(
        HttpStatusCode.Forbidden,
        ProblemDetail(
            type = "about:blank",
            title = "Forbidden",
            status = HttpStatusCode.Forbidden.value,
            detail = detail,
            instance = request.local.uri
        )
    )
}

