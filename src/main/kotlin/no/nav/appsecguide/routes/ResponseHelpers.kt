package no.nav.appsecguide.routes

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.response.*
import no.nav.appsecguide.domain.ProblemDetail

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

suspend fun ApplicationCall.respondInternalServerError(errorContext: String, exception: Exception) {
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

