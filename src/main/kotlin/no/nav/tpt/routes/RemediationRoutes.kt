package no.nav.tpt.routes

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.utils.io.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import no.nav.tpt.domain.remediation.RemediationException
import no.nav.tpt.domain.remediation.RemediationRequest
import no.nav.tpt.plugins.ServiceUnavailableException
import no.nav.tpt.plugins.dependencies
import org.slf4j.LoggerFactory

private val logger = LoggerFactory.getLogger("no.nav.tpt.routes.RemediationRoutes")

@Serializable
private data class SseErrorPayload(val code: String, val detail: String)

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
                } catch (e: RemediationException.AiServiceException) {
                    logger.error("AI service error streaming remediation for CVE ${request.cveId}", e)
                    val payload = Json.encodeToString(SseErrorPayload("ai_service_error", "AI service is temporarily unavailable"))
                    writeStringUtf8("event: error\ndata: $payload\n\n")
                    flush()
                } catch (e: RemediationException.DataFetchException) {
                    logger.error("Data fetch error streaming remediation for CVE ${request.cveId}", e)
                    val payload = Json.encodeToString(SseErrorPayload("data_fetch_error", "Failed to fetch vulnerability data"))
                    writeStringUtf8("event: error\ndata: $payload\n\n")
                    flush()
                } catch (e: Exception) {
                    logger.error("Error streaming remediation for CVE ${request.cveId}", e)
                    val payload = Json.encodeToString(SseErrorPayload("internal_error", "Failed to generate remediation"))
                    writeStringUtf8("event: error\ndata: $payload\n\n")
                    flush()
                }
            }
        }
    }
}
