package no.nav.tpt.infrastructure.vulnrichment

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import no.nav.tpt.plugins.LeaderElection
import org.slf4j.LoggerFactory
import java.time.LocalDateTime
import java.util.concurrent.ConcurrentHashMap

class VulnrichmentSyncService(
    private val client: VulnrichmentClient,
    private val repository: VulnrichmentRepository,
    private val leaderElection: LeaderElection,
    private val backgroundScope: CoroutineScope = CoroutineScope(Dispatchers.IO + SupervisorJob()),
) {
    private val logger = LoggerFactory.getLogger(VulnrichmentSyncService::class.java)
    private val inFlight: MutableSet<String> = ConcurrentHashMap.newKeySet()

    suspend fun ensureCached(cveIds: List<String>) {
        if (cveIds.isEmpty()) return
        val cached = repository.getVulnrichmentDataBatch(cveIds)
        val toFetch = cveIds.filter { it !in cached }.filter { inFlight.add(it) }
        if (toFetch.isEmpty()) return

        logger.debug("Scheduling background Vulnrichment fetch for ${toFetch.size} uncached CVEs")
        backgroundScope.launch {
            try {
                val fetched = toFetch.mapNotNull { client.fetchCveData(it) }
                if (fetched.isNotEmpty()) repository.upsertVulnrichmentData(fetched)
            } catch (e: Exception) {
                logger.warn("Background Vulnrichment cache warming failed: ${e.message}")
            } finally {
                inFlight.removeAll(toFetch.toSet())
            }
        }
    }

    suspend fun refreshStale(olderThan: LocalDateTime = LocalDateTime.now().minusDays(30)) {
        leaderElection.ifLeader {
            val stale = repository.getStaleVulnrichmentIds(olderThan)
            if (stale.isEmpty()) return@ifLeader

            logger.info("Refreshing ${stale.size} stale Vulnrichment records")
            val refreshed = stale.mapNotNull { client.fetchCveData(it) }
            if (refreshed.isNotEmpty()) repository.upsertVulnrichmentData(refreshed)
        }
    }
}

