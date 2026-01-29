package no.nav.tpt.plugins

import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.get
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.slf4j.LoggerFactory
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.time.Duration.Companion.seconds

open class LeaderElection(private val httpClient: HttpClient) {
    private val logger = LoggerFactory.getLogger(LeaderElection::class.java)
    private val electorUrl = System.getenv("ELECTOR_GET_URL") ?: ""
    private val hostname = try {
        InetAddress.getLocalHost().hostName
    } catch (e: Exception) {
        logger.warn("Failed to get hostname", e)
        "unknown"
    }

    private val cachedLeaderStatus = AtomicBoolean(false)
    private val checkIntervalSeconds = 60L
    private val checksStarted = AtomicBoolean(false)

    fun startLeaderElectionChecks(scope: CoroutineScope) {
        if (electorUrl.isEmpty()) {
            logger.info("ELECTOR_GET_URL not set, assuming single instance (leader)")
            cachedLeaderStatus.set(true)
            return
        }

        if (checksStarted.getAndSet(true)) {
            logger.debug("Leader election checks already started, skipping")
            return
        }

        scope.launch {
            logger.info("Starting leader election checks every ${checkIntervalSeconds}s")
            while (isActive) {
                checkLeaderStatus()
                delay(checkIntervalSeconds.seconds)
            }
        }
    }

    private suspend fun checkLeaderStatus() {
        try {
            val response = httpClient.get(electorUrl)
            val leaderInfo: LeaderInfo = response.body()
            val isLeader = hostname == leaderInfo.name
            val wasLeader = cachedLeaderStatus.getAndSet(isLeader)

            if (isLeader && !wasLeader) {
                logger.info("Leadership acquired: This pod ($hostname) is now the leader")
            } else if (!isLeader && wasLeader) {
                logger.info("Leadership lost: This pod ($hostname) is no longer the leader. Leader is: ${leaderInfo.name}")
            } else if (isLeader) {
                logger.debug("This pod ($hostname) is the leader")
            } else {
                logger.debug("This pod ($hostname) is not the leader. Leader is: ${leaderInfo.name}")
            }
        } catch (e: Exception) {
            logger.warn("Failed to check leader election status", e)
            cachedLeaderStatus.set(false)
        }
    }

    open fun isLeader(): Boolean {
        return cachedLeaderStatus.get()
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