package no.nav.tpt.infrastructure.teamkatalogen

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import org.slf4j.LoggerFactory

class TeamkatalogenClient(
    private val httpClient: HttpClient,
    private val baseUrl: String
) {
    private val logger = LoggerFactory.getLogger(TeamkatalogenClient::class.java)

    suspend fun getMembershipByEmail(email: String): MembershipResponse {
        logger.debug("Fetching membership for email: $email")

        val response = httpClient.get("$baseUrl/member/membership/byUserEmail") {
            parameter("email", email)
        }

        val apiResponse: TeamkatalogenApiResponse = response.body()

        // Flatten the nested naisTeams arrays into a single list
        val allNaisTeams = apiResponse.teams.flatMap { it.naisTeams }

        // Extract all cluster IDs
        val clusterIds = apiResponse.clusters.map { it.id }

        // Extract productAreaIds from clusters (where available)
        val clusterProductAreaIds = apiResponse.clusters.mapNotNull { it.productAreaId }

        // Extract direct productArea IDs
        val directProductAreaIds = apiResponse.productAreas.map { it.id }

        return MembershipResponse(
            naisTeams = allNaisTeams,
            clusterIds = clusterIds,
            clusterProductAreaIds = clusterProductAreaIds,
            productAreaIds = directProductAreaIds
        )
    }

    suspend fun getSubteamsByProductAreaId(productAreaId: String): SubteamsResponse {
        logger.debug("Fetching subteams for productArea: $productAreaId")

        val response = httpClient.get("$baseUrl/team") {
            parameter("productAreaId", productAreaId)
            parameter("status", "ACTIVE")
        }

        return response.body()
    }

    suspend fun getSubteamsByClusterId(clusterId: String): SubteamsResponse {
        logger.debug("Fetching subteams for cluster: $clusterId")

        val response = httpClient.get("$baseUrl/team") {
            parameter("clusterId", clusterId)
            parameter("status", "ACTIVE")
        }

        return response.body()
    }
}

