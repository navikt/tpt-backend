package no.nav.tpt.routes

import io.ktor.server.auth.authenticate
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sse.*
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.onEach
import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.sse.SseEvent
import no.nav.tpt.infrastructure.sse.SseEventBus

fun Route.sseRoutes(sseEventBus: SseEventBus) {
    val json = Json { ignoreUnknownKeys = true }

    authenticate("auth-bearer") {
        sse("/events") {
            sseEventBus.events.onEach { event ->
                val eventType = when (event) {
                    is SseEvent.TeamSyncStarted -> "team_sync_started"
                    is SseEvent.TeamSyncComplete -> "team_sync_complete"
                    is SseEvent.GcveSyncComplete -> "gcve_sync_complete"
                }
                send(io.ktor.sse.ServerSentEvent(data = json.encodeToString(SseEvent.serializer(), event), event = eventType))
            }.collect()
        }
    }
}
