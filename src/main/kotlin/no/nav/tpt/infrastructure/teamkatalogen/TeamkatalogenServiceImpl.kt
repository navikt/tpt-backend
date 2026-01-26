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

    override suspend fun getSubteamNaisTeams(productAreaIds: List<String>): List<String> = coroutineScope {
        // Deduplicate productAreaIds
        val uniqueProductAreaIds = productAreaIds.distinct()
        
        logger.debug("Fetching subteams for ${uniqueProductAreaIds.size} unique product areas")

        // Fetch subteams for all productAreas in parallel
        val productAreaTeams = uniqueProductAreaIds.map { productAreaId ->
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
        val allSubteams = productAreaTeams.flatMap { it.await() }

        // Extract and deduplicate naisTeams
        val allNaisTeams = allSubteams.flatMap { it.naisTeams }.distinct()

        logger.debug("Found ${allNaisTeams.size} unique NAIS teams from ${uniqueProductAreaIds.size} product areas")

        allNaisTeams
    }
}

