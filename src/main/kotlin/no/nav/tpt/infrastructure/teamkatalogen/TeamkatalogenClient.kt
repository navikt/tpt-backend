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

        return response.body()
    }
}

