package no.nav.tpt.plugins

import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationStopping
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import no.nav.tpt.infrastructure.sse.SseEventLogListener
import org.slf4j.LoggerFactory
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

fun Application.configureSseEventLog() {
    val listener = dependencies.sseEventLogListener ?: return
    val eventLog = dependencies.sseEventLogRepository
    val leaderElection = dependencies.leaderElection
    val logger = LoggerFactory.getLogger("SseEventLog")

    leaderElection.startLeaderElectionChecks(this)
    listener.start(this)

    launch {
        delay(60.seconds)
        while (isActive) {
            try {
                if (leaderElection.isLeader()) {
                    val deleted = eventLog.deleteOlderThanOneHour()
                    if (deleted > 0) {
                        logger.info("Deleted $deleted expired SSE events")
                    }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                logger.error("Failed to delete expired SSE events", e)
            }
            delay(15.minutes)
        }
    }

    monitor.subscribe(ApplicationStopping) {
        listener.stop()
    }
}
