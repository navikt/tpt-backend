package no.nav.tpt.infrastructure.teamkatalogen

import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import org.slf4j.LoggerFactory

class TeamkatalogenServiceImpl(
    private val client: TeamkatalogenClient
) : TeamkatalogenService {
    private val logger = LoggerFactory.getLogger(TeamkatalogenServiceImpl::class.java)

    override suspend fun getMembershipByEmail(email: String): MembershipResponse {
        return client.getMembershipByEmail(email)
    }

    override suspend fun getSubteamNaisTeams(clusterIds: List<String>, productAreaIds: List<String>): List<String> = coroutineScope {
        // Combine and deduplicate all IDs
        val allIds = (clusterIds + productAreaIds).distinct()
        
        logger.debug("Fetching subteams for ${clusterIds.size} clusters and ${productAreaIds.size} product areas (${allIds.size} total)")

        // Fetch subteams for clusters
        val clusterTeams = clusterIds.distinct().map { clusterId ->
            async {
                try {
                    client.getSubteamsByClusterId(clusterId).content
                } catch (e: Exception) {
                    logger.warn("Failed to fetch subteams for cluster $clusterId: ${e.message}")
                    emptyList()
                }
            }
        }

        // Fetch subteams for productAreas
        val productAreaTeams = productAreaIds.distinct().map { productAreaId ->
            async {
                try {
                    client.getSubteamsByProductAreaId(productAreaId).content
                } catch (e: Exception) {
                    logger.warn("Failed to fetch subteams for productArea $productAreaId: ${e.message}")
                    emptyList()
                }
            }
        }

        // Await all results and flatten
        val allSubteams = (clusterTeams + productAreaTeams).flatMap { it.await() }

        // Extract and deduplicate naisTeams
        val allNaisTeams = allSubteams.flatMap { it.naisTeams }.distinct()

        logger.debug("Found ${allNaisTeams.size} unique NAIS teams from ${clusterIds.size} clusters and ${productAreaIds.size} product areas")

        allNaisTeams
    }
}

