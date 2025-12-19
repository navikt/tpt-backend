package no.nav.tpt.plugins

import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.get
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import java.net.InetAddress

class LeaderElection(private val httpClient: HttpClient) {
    private val logger = LoggerFactory.getLogger(LeaderElection::class.java)
    private val electorUrl = System.getenv("ELECTOR_GET_URL") ?: ""
    private val hostname = try {
        InetAddress.getLocalHost().hostName
    } catch (e: Exception) {
        logger.warn("Failed to get hostname", e)
        "unknown"
    }

    suspend fun isLeader(): Boolean {
        if (electorUrl.isEmpty()) {
            logger.debug("ELECTOR_GET_URL not set, assuming single instance (leader)")
            return true
        }

        return try {
            val response = httpClient.get(electorUrl)
            val leaderInfo: LeaderInfo = response.body()
            val isLeader = hostname == leaderInfo.name

            if (isLeader) {
                logger.debug("This pod ($hostname) is the leader")
            } else {
                logger.debug("This pod ($hostname) is not the leader. Leader is: ${leaderInfo.name}")
            }

            isLeader
        } catch (e: Exception) {
            logger.warn("Failed to check leader election status, assuming not leader", e)
            false
        }
    }

    suspend fun <T> ifLeader(operation: suspend () -> T): T? {
        return if (isLeader()) {
            operation()
        } else {
            null
        }
    }

    @Serializable
    private data class LeaderInfo(
        @SerialName("name") val name: String
    )
}