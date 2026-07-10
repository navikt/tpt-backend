package no.nav.tpt.routes

import io.ktor.server.auth.authenticate
import io.ktor.server.auth.principal
import io.ktor.server.routing.*
import io.ktor.server.sse.*
import io.ktor.sse.ServerSentEvent
import io.ktor.utils.io.ClosedWriteChannelException
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.onEach
import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.sse.SseEvent
import no.nav.tpt.infrastructure.sse.SseEventBus
import no.nav.tpt.plugins.TokenPrincipal
import no.nav.tpt.plugins.dependencies
import kotlin.time.Duration.Companion.seconds

fun Route.sseRoutes(sseEventBus: SseEventBus) {
    val json = Json { ignoreUnknownKeys = true }

    authenticate("auth-bearer") {
        sse("/events") {
            val principal = call.principal<TokenPrincipal>()!!
            val email = principal.preferredUsername ?: return@sse

            val userContext = call.dependencies.userContextService.getUserContext(email, principal.groups)
            val userTeamSlugs = userContext.teams.toSet()

            heartbeat {
                period = 15.seconds
                event = ServerSentEvent(comments = "heartbeat")
            }

            try {
                sseEventBus.events
                    .filter { event ->
                        when (event) {
                            is SseEvent.TeamSyncStarted -> event.teamSlug in userTeamSlugs
                            is SseEvent.TeamSyncComplete -> event.teamSlug in userTeamSlugs
                            is SseEvent.GcveSyncComplete -> true
                        }
                    }
                    .onEach { event ->
                        val eventType = when (event) {
                            is SseEvent.TeamSyncStarted -> "team_sync_started"
                            is SseEvent.TeamSyncComplete -> "team_sync_complete"
                            is SseEvent.GcveSyncComplete -> "gcve_sync_complete"
                        }
                        send(ServerSentEvent(data = json.encodeToString(SseEvent.serializer(), event), event = eventType))
                    }
                    .collect()
            } catch (_: ClosedWriteChannelException) {
                // Client disconnected — normal for SSE when the browser tab is closed or refreshed.
            }
        }
    }
}
