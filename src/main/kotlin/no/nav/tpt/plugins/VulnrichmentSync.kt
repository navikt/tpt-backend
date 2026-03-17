package no.nav.tpt.plugins

import io.ktor.server.application.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.slf4j.LoggerFactory
import kotlin.time.Duration.Companion.hours

fun Application.configureVulnrichmentSync() {
    val logger = LoggerFactory.getLogger("VulnrichmentSync")
    val syncService = dependencies.vulnrichmentSyncService

    launch {
        delay(5.hours)
        while (true) {
            try {
                syncService.sync()
            } catch (e: Exception) {
                logger.error("Vulnrichment sync failed: ${e.message}", e)
            }
            delay(24.hours)
        }
    }
}
