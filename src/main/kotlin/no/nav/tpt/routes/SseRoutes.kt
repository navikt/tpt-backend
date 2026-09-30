package no.nav.tpt.routes

import io.ktor.server.application.createRouteScopedPlugin
import io.ktor.server.auth.authenticate
import io.ktor.server.auth.principal
import io.ktor.server.routing.*
import io.ktor.server.sse.*
import io.ktor.sse.ServerSentEvent
import io.ktor.utils.io.ClosedWriteChannelException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.sse.SseEvent
import no.nav.tpt.infrastructure.sse.SseEventBus
import no.nav.tpt.infrastructure.sse.SseEventEnvelope
import no.nav.tpt.infrastructure.sse.SseEventLogRepository
import no.nav.tpt.plugins.BadRequestException
import no.nav.tpt.plugins.TokenPrincipal
import no.nav.tpt.plugins.dependencies
import kotlin.time.Duration.Companion.seconds

private val LastEventIdValidation = createRouteScopedPlugin("LastEventIdValidation") {
    onCall { call ->
        val header = call.request.headers["Last-Event-ID"]
        val id = header?.toLongOrNull()
        if (header != null && (id == null || id < 0)) {
            throw BadRequestException("Last-Event-ID must be a non-negative integer")
        }
    }
}

fun Route.sseRoutes(sseEventBus: SseEventBus) {
    val json = Json { ignoreUnknownKeys = true }

    authenticate("auth-bearer") {
        install(LastEventIdValidation)
        sse("/events") {
            val principal = call.principal<TokenPrincipal>()!!
            val email = principal.preferredUsername ?: return@sse
            val lastEventId = call.request.headers["Last-Event-ID"]?.toLong()

            val userContext = call.dependencies.userContextService.getUserContext(email, principal.groups)
            val userTeamSlugs = userContext.teams.toSet()

            heartbeat {
                period = 15.seconds
                event = ServerSentEvent(comments = "heartbeat")
            }

            try {
                val liveEvents = Channel<SseEventEnvelope>(Channel.UNLIMITED)
                val subscription = launch(start = CoroutineStart.UNDISPATCHED) {
                    sseEventBus.events.collect { liveEvents.send(it) }
                }
                try {
                    var lastSentId = lastEventId ?: 0L
                    if (lastEventId != null) {
                        while (true) {
                            val replay = call.dependencies.sseEventLogRepository.eventsAfter(lastSentId)
                            replay.forEach { envelope ->
                                lastSentId = envelope.id
                                if (isRelevant(envelope.event, userTeamSlugs)) {
                                    send(toServerSentEvent(envelope, json))
                                }
                            }
                            if (replay.size < SseEventLogRepository.BATCH_SIZE) break
                        }
                    }

                    for (envelope in liveEvents) {
                        if (envelope.id <= lastSentId) continue
                        lastSentId = envelope.id
                        if (isRelevant(envelope.event, userTeamSlugs)) {
                            send(toServerSentEvent(envelope, json))
                        }
                    }
                } finally {
                    subscription.cancel()
                    liveEvents.cancel()
                }
            } catch (_: ClosedWriteChannelException) {
                // Client disconnected — normal for SSE when the browser tab is closed or refreshed.
            }
        }
    }
}

private fun isRelevant(event: SseEvent, userTeamSlugs: Set<String>): Boolean =
    when (event) {
        is SseEvent.TeamSyncStarted -> event.teamSlug in userTeamSlugs
        is SseEvent.TeamSyncComplete -> event.teamSlug in userTeamSlugs
        is SseEvent.GcveSyncComplete -> true
        is SseEvent.GitHubVulnSyncStarted -> event.teams.any { it in userTeamSlugs }
        is SseEvent.GitHubVulnSyncComplete -> event.teams.any { it in userTeamSlugs }
    }

private fun toServerSentEvent(
    envelope: SseEventEnvelope,
    json: Json,
): ServerSentEvent =
    ServerSentEvent(
        id = envelope.id.toString(),
        data = json.encodeToString(SseEvent.serializer(), envelope.event),
        event = envelope.type,
    )
