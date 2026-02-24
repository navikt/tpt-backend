package no.nav.tpt.routes

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.utils.io.*
import no.nav.tpt.domain.remediation.RemediationRequest
import no.nav.tpt.plugins.InternalServerException
import no.nav.tpt.plugins.ServiceUnavailableException
import no.nav.tpt.plugins.dependencies

fun Route.remediationRoutes() {
    authenticate("auth-bearer") {
        post("/vulnerabilities/remediation") {
            val remediationService = call.dependencies.remediationService
                ?: throw ServiceUnavailableException("AI remediation service is not configured")

            val request = call.receive<RemediationRequest>()

            call.response.cacheControl(CacheControl.NoCache(null))
            call.respondBytesWriter(contentType = ContentType.Text.EventStream) {
                try {
                    remediationService.streamRemediation(request).collect { chunk ->
                        val escaped = chunk.replace("\n", "\ndata: ")
                        writeStringUtf8("data: $escaped\n\n")
                        flush()
                    }
                    writeStringUtf8("event: done\ndata: \n\n")
                    flush()
                } catch (e: Exception) {
                    writeStringUtf8("event: error\ndata: ${e.message?.replace("\n", " ")}\n\n")
                    flush()
                }
            }
        }
    }
}
