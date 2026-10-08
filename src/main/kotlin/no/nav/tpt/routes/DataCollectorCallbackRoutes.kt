package no.nav.tpt.routes

import io.ktor.http.HttpStatusCode
import io.ktor.server.auth.authenticate
import io.ktor.server.request.receiveText
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.RoutingCall
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.datacollector.CheckResultsForRepo
import no.nav.tpt.infrastructure.datacollector.GitHubSyncSignal
import no.nav.tpt.infrastructure.github.GitHubRepositoryMessage
import no.nav.tpt.infrastructure.sse.SseEvent
import no.nav.tpt.metrics.TPTMetrics
import no.nav.tpt.plugins.BadRequestException
import no.nav.tpt.plugins.dependencies

private val callbackJson = Json { ignoreUnknownKeys = true }

fun Route.dataCollectorCallbackRoutes() {
    authenticate("data-collector-bearer") {
        route("/callbacks") {
            post("/github/vulnerabilities") {
                val message = call.decodeBody<GitHubRepositoryMessage>()
                if (message.nameWithOwner.isBlank()) {
                    throw BadRequestException("nameWithOwner must not be blank")
                }
                call.dependencies.gitHubRepository.upsertRepositoryData(message)
                call.respond(HttpStatusCode.NoContent)
            }

            post("/github/sync/started") {
                val signal = call.decodeBody<GitHubSyncSignal>()
                call.dependencies.sseEventLogRepository.publish(SseEvent.GitHubVulnSyncStarted(signal.teams, signal.timestamp))
                call.respond(HttpStatusCode.NoContent)
            }

            post("/github/sync/complete") {
                val signal = call.decodeBody<GitHubSyncSignal>()
                call.dependencies.sseEventLogRepository.publish(SseEvent.GitHubVulnSyncComplete(signal.teams, signal.timestamp))
                call.respond(HttpStatusCode.NoContent)
            }

            post("/checks") {
                val checkResults = call.decodeBody<CheckResultsForRepo>()
                if (checkResults.repoName.isBlank()) {
                    throw BadRequestException("repoName must not be blank")
                }
                try {
                    call.dependencies.dataCollectorRepository.insert(checkResults)
                } catch (e: Exception) {
                    TPTMetrics.checksPersistingFailed()
                    throw e
                }
                TPTMetrics.checksPersisted(checkResults.results.size)
                call.respond(HttpStatusCode.NoContent)
            }
        }
    }
}

private suspend inline fun <reified T> RoutingCall.decodeBody(): T =
    callbackJson.decodeFromString<T>(receiveText())
