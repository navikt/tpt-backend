package no.nav.tpt.infrastructure.sse

import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class SseEventBusTest {
    @Test
    fun `should deliver events with ids to all collectors`() = runBlocking {
        val eventBus = SseEventBus()
        val receivedA = mutableListOf<SseEventEnvelope>()
        val receivedB = mutableListOf<SseEventEnvelope>()

        val jobA = launch { eventBus.events.collect { receivedA.add(it) } }
        val jobB = launch { eventBus.events.collect { receivedB.add(it) } }
        yield()

        val envelope = SseEventEnvelope(25, SseEvent.TeamSyncStarted("team-a", "2024-01-01T00:00:00Z"))
        eventBus.emit(envelope)
        yield()

        jobA.cancel()
        jobB.cancel()

        assertEquals(listOf(envelope), receivedA)
        assertEquals(listOf(envelope), receivedB)
        assertIs<SseEvent.TeamSyncStarted>(receivedA.single().event)
        assertEquals("team-a", (receivedA.single().event as SseEvent.TeamSyncStarted).teamSlug)
    }

    @Test
    fun `should preserve event order`() = runBlocking {
        val eventBus = SseEventBus()
        val received = mutableListOf<SseEventEnvelope>()
        val job = launch { eventBus.events.collect { received.add(it) } }
        yield()

        eventBus.emit(SseEventEnvelope(1, SseEvent.TeamSyncStarted("team-a", "t1")))
        eventBus.emit(SseEventEnvelope(2, SseEvent.TeamSyncComplete("team-a", "t2")))
        yield()
        job.cancel()

        assertEquals(listOf(1L, 2L), received.map { it.id })
        assertIs<SseEvent.TeamSyncStarted>(received[0].event)
        assertIs<SseEvent.TeamSyncComplete>(received[1].event)
    }

    @Test
    fun `should not replay events emitted before a collector starts`() = runBlocking {
        val eventBus = SseEventBus()
        eventBus.emit(SseEventEnvelope(1, SseEvent.TeamSyncStarted("team-a", "t")))

        val received = mutableListOf<SseEventEnvelope>()
        val job = launch { eventBus.events.collect { received.add(it) } }
        yield()
        job.cancel()

        assertEquals(0, received.size)
    }
}
