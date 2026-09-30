package no.nav.tpt.infrastructure.sse

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.postgresql.PGConnection
import org.slf4j.LoggerFactory
import java.sql.Connection
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.time.Duration.Companion.seconds

class SseEventLogListener(
    private val connectionFactory: () -> Connection,
    private val eventLog: SseEventLogRepository,
    private val eventBus: SseEventBus,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    private val logger = LoggerFactory.getLogger(SseEventLogListener::class.java)
    private val healthy = AtomicBoolean(false)
    private var listenerJob: Job? = null

    fun start(scope: CoroutineScope) {
        if (listenerJob != null) return
        listenerJob = scope.launch(dispatcher) {
            var lastSeenId: Long? = null
            while (isActive) {
                try {
                    connectionFactory().use { connection ->
                        connection.createStatement().use { statement ->
                            statement.execute("LISTEN sse_event_log")
                        }
                        val postgresConnection = connection.unwrap(PGConnection::class.java)
                        val startingCursor = lastSeenId ?: eventLog.latestEventId()
                        lastSeenId = startingCursor
                        setHealthy(true)
                        logger.info("SSE event log listener connected at id=$startingCursor")

                        lastSeenId = publishEventsAfter(startingCursor)
                        while (isActive) {
                            val notifications = postgresConnection.getNotifications(1000)
                            if (!notifications.isNullOrEmpty()) {
                                lastSeenId = publishEventsAfter(checkNotNull(lastSeenId))
                            }
                        }
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    setHealthy(false)
                    logger.error("SSE event log listener disconnected; reconnecting", e)
                    delay(5.seconds)
                }
            }
        }
    }

    fun stop() {
        listenerJob?.cancel()
        listenerJob = null
        setHealthy(false)
    }

    fun isHealthy(): Boolean = healthy.get()

    private suspend fun publishEventsAfter(lastSeenId: Long): Long {
        var cursor = lastSeenId
        while (true) {
            val events = eventLog.eventsAfter(cursor)
            if (events.isEmpty()) return cursor
            for (event in events) {
                eventBus.emit(event)
                cursor = event.id
            }
            if (events.size < SseEventLogRepository.BATCH_SIZE) return cursor
        }
    }

    private fun setHealthy(value: Boolean) {
        healthy.set(value)
        no.nav.tpt.metrics.TPTMetrics.setSseEventListenerHealthy(value)
    }
}
