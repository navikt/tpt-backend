package no.nav.tpt.infrastructure.sse

interface SseEventPublisher {
    suspend fun publish(event: SseEvent): SseEventEnvelope
}
