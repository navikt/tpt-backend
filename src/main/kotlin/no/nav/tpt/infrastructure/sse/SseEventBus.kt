package no.nav.tpt.infrastructure.sse

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.channels.BufferOverflow

class SseEventBus {
    private val _events = MutableSharedFlow<SseEventEnvelope>(
        extraBufferCapacity = 256,
        onBufferOverflow = BufferOverflow.SUSPEND,
    )
    val events: SharedFlow<SseEventEnvelope> = _events.asSharedFlow()

    suspend fun emit(event: SseEventEnvelope) = _events.emit(event)
}
