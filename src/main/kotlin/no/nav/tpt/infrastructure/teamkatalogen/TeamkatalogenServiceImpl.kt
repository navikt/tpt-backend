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

    override suspend fun getSubteamNaisTeams(
        clusters: List<TeamkatalogenEntity>,
        productAreas: List<TeamkatalogenEntity>
    ): List<String> = coroutineScope {
        val clusterTeams = clusters.map { cluster ->
            async {
                try {
                    client.getSubteamsByClusterId(cluster.id).content
                } catch (e: Exception) {
                    logger.warn("Failed to fetch subteams for cluster ${cluster.id}: ${e.message}")
                    emptyList()
                }
            }
        }

        val productAreaTeams = productAreas.map { productArea ->
            async {
                try {
                    client.getSubteamsByProductAreaId(productArea.id).content
                } catch (e: Exception) {
                    logger.warn("Failed to fetch subteams for productArea ${productArea.id}: ${e.message}")
                    emptyList()
                }
            }
        }

        // Await all results and flatten
        val allSubteams = (clusterTeams + productAreaTeams).flatMap { it.await() }

        // Extract and deduplicate naisTeams
        val allNaisTeams = allSubteams.flatMap { it.naisTeams }.distinct()

        logger.debug("Found ${allNaisTeams.size} unique NAIS teams from ${clusters.size} clusters and ${productAreas.size} product areas")

        allNaisTeams
    }
}

