package no.nav.tpt.plugins

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import kotlinx.serialization.SerializationException
import no.nav.tpt.domain.ProblemDetail
import org.slf4j.LoggerFactory

private val logger = LoggerFactory.getLogger("no.nav.tpt.plugins.StatusPages")

class BadRequestException(message: String) : Exception(message)
class UnauthorizedException(message: String) : Exception(message)
class ForbiddenException(message: String) : Exception(message)
class InternalServerException(val context: String, cause: Throwable) : Exception("$context: ${cause.message}", cause)

fun Application.configureStatusPages() {
    install(StatusPages) {
        exception<BadRequestException> { call, cause ->
            call.respond(
                HttpStatusCode.BadRequest,
                ProblemDetail(
                    type = "about:blank",
                    title = "Bad Request",
                    status = HttpStatusCode.BadRequest.value,
                    detail = cause.message,
                    instance = call.request.uri
                )
            )
        }

        exception<UnauthorizedException> { call, cause ->
            call.respond(
                HttpStatusCode.Unauthorized,
                ProblemDetail(
                    type = "about:blank",
                    title = "Unauthorized",
                    status = HttpStatusCode.Unauthorized.value,
                    detail = cause.message,
                    instance = call.request.uri
                )
            )
        }

        exception<ForbiddenException> { call, cause ->
            call.respond(
                HttpStatusCode.Forbidden,
                ProblemDetail(
                    type = "about:blank",
                    title = "Forbidden",
                    status = HttpStatusCode.Forbidden.value,
                    detail = cause.message,
                    instance = call.request.uri
                )
            )
        }

        exception<InternalServerException> { call, cause ->
            logger.error("${cause.context} for request ${call.request.httpMethod.value} ${call.request.uri}", cause.cause)
            call.respond(
                HttpStatusCode.InternalServerError,
                ProblemDetail(
                    type = "about:blank",
                    title = "Internal Server Error",
                    status = HttpStatusCode.InternalServerError.value,
                    detail = cause.message,
                    instance = call.request.uri
                )
            )
        }

        exception<SerializationException> { call, cause ->
            logger.warn("Serialization error for request ${call.request.httpMethod.value} ${call.request.uri}", cause)
            call.respond(
                HttpStatusCode.BadRequest,
                ProblemDetail(
                    type = "about:blank",
                    title = "Bad Request",
                    status = HttpStatusCode.BadRequest.value,
                    detail = "Invalid request format: ${cause.message}",
                    instance = call.request.uri
                )
            )
        }

        exception<Exception> { call, cause ->
            logger.error("Unhandled exception for request ${call.request.httpMethod.value} ${call.request.uri}", cause)
            call.respond(
                HttpStatusCode.InternalServerError,
                ProblemDetail(
                    type = "about:blank",
                    title = "Internal Server Error",
                    status = HttpStatusCode.InternalServerError.value,
                    detail = cause.message,
                    instance = call.request.uri
                )
            )
        }
    }
}
