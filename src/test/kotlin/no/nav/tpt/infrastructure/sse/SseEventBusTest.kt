package no.nav.tpt.infrastructure.sse

import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class SseEventBusTest {

    @Test
    fun `should deliver emitted events to all collectors`() = runBlocking {
        val eventBus = SseEventBus()
        val receivedA = mutableListOf<SseEvent>()
        val receivedB = mutableListOf<SseEvent>()

        val jobA = launch { eventBus.events.collect { receivedA.add(it) } }
        val jobB = launch { eventBus.events.collect { receivedB.add(it) } }
        yield()

        eventBus.emit(SseEvent.TeamSyncStarted("team-a", "2024-01-01T00:00:00Z"))
        yield()

        jobA.cancel()
        jobB.cancel()

        assertEquals(1, receivedA.size)
        assertEquals(1, receivedB.size)
        val eventA = receivedA[0]
        assertIs<SseEvent.TeamSyncStarted>(eventA)
        assertEquals("team-a", eventA.teamSlug)
    }

    @Test
    fun `should deliver TeamSyncComplete event`() = runBlocking {
        val eventBus = SseEventBus()
        val received = mutableListOf<SseEvent>()

        val job = launch { eventBus.events.collect { received.add(it) } }
        yield()

        eventBus.emit(SseEvent.TeamSyncComplete("team-b", "2024-01-01T01:00:00Z"))
        yield()

        job.cancel()

        assertEquals(1, received.size)
        val event = received[0]
        assertIs<SseEvent.TeamSyncComplete>(event)
        assertEquals("team-b", event.teamSlug)
    }

    @Test
    fun `should deliver GcveSyncComplete event`() = runBlocking {
        val eventBus = SseEventBus()
        val received = mutableListOf<SseEvent>()

        val job = launch { eventBus.events.collect { received.add(it) } }
        yield()

        eventBus.emit(SseEvent.GcveSyncComplete(42, "2024-01-01T02:00:00Z"))
        yield()

        job.cancel()

        assertEquals(1, received.size)
        val event = received[0]
        assertIs<SseEvent.GcveSyncComplete>(event)
        assertEquals(42, event.cveCount)
    }

    @Test
    fun `should deliver multiple events in order`() = runBlocking {
        val eventBus = SseEventBus()
        val received = mutableListOf<SseEvent>()

        val job = launch { eventBus.events.collect { received.add(it) } }
        yield()

        eventBus.emit(SseEvent.TeamSyncStarted("team-a", "2024-01-01T00:00:00Z"))
        eventBus.emit(SseEvent.TeamSyncComplete("team-a", "2024-01-01T00:01:00Z"))
        yield()

        job.cancel()

        assertEquals(2, received.size)
        assertIs<SseEvent.TeamSyncStarted>(received[0])
        assertIs<SseEvent.TeamSyncComplete>(received[1])
    }

    @Test
    fun `should not deliver events to collectors that start after emission`() = runBlocking {
        val eventBus = SseEventBus()

        eventBus.emit(SseEvent.TeamSyncStarted("team-a", "2024-01-01T00:00:00Z"))

        val received = mutableListOf<SseEvent>()
        val job = launch { eventBus.events.collect { received.add(it) } }
        yield()

        job.cancel()

        assertEquals(0, received.size)
    }
}
