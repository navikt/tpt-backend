package no.nav.tpt.infrastructure.sse

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.channels.BufferOverflow
import org.slf4j.LoggerFactory

class SseEventBus {
    private val logger = LoggerFactory.getLogger(SseEventBus::class.java)
    private val _events = MutableSharedFlow<SseEvent>(
        extraBufferCapacity = 64,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val events: SharedFlow<SseEvent> = _events.asSharedFlow()

    fun emit(event: SseEvent) {
        val emitted = _events.tryEmit(event)
        if (!emitted) {
            logger.warn("SSE event dropped (no subscribers or buffer full): $event")
        }
    }
}
