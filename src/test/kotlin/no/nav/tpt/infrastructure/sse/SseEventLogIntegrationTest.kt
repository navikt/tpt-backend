package no.nav.tpt.infrastructure.sse

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import kotlinx.coroutines.withTimeout
import org.flywaydb.core.Flyway
import org.jetbrains.exposed.v1.jdbc.Database
import org.junit.jupiter.api.BeforeAll
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@Testcontainers
class SseEventLogIntegrationTest {
    companion object {
        @Container
        private val postgres = PostgreSQLContainer<Nothing>("postgres:17-alpine").apply {
            withDatabaseName("sse_test")
            withUsername("test")
            withPassword("test")
        }

        private lateinit var database: Database

        @JvmStatic
        @BeforeAll
        fun setUp() {
            postgres.start()
            val dataSource = HikariDataSource(
                HikariConfig().apply {
                    jdbcUrl = postgres.jdbcUrl
                    username = postgres.username
                    password = postgres.password
                    driverClassName = "org.postgresql.Driver"
                }
            )
            Flyway.configure().dataSource(dataSource).load().migrate()
            database = Database.connect(dataSource)
        }
    }

    @Test
    fun `should publish a logged event to listeners on separate connections`() = runBlocking {
        val eventLog = SseEventLogRepository(database)
        val eventBusA = SseEventBus()
        val eventBusB = SseEventBus()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val listenerA = listener(eventLog, eventBusA)
        val listenerB = listener(eventLog, eventBusB)
        val receivedA = async(start = kotlinx.coroutines.CoroutineStart.LAZY) { eventBusA.events.first() }
        val receivedB = async(start = kotlinx.coroutines.CoroutineStart.LAZY) { eventBusB.events.first() }

        try {
            receivedA.start()
            receivedB.start()
            yield()
            listenerA.start(scope)
            listenerB.start(scope)
            withTimeout(10_000) {
                while (!listenerA.isHealthy() || !listenerB.isHealthy()) {
                    delay(10)
                }
            }

            val event = SseEvent.TeamSyncStarted("cross-pod-team", "2026-09-29T00:00:00Z")
            val published = eventLog.publish(event)

            val eventA = withTimeout(10_000) { receivedA.await() }
            val eventB = withTimeout(10_000) { receivedB.await() }
            assertEquals(published, eventA)
            assertEquals(published, eventB)
            assertEquals(listOf(published), eventLog.eventsAfter(published.id - 1))
            assertTrue(listenerA.isHealthy())
            assertTrue(listenerB.isHealthy())
        } finally {
            listenerA.stop()
            listenerB.stop()
            receivedA.cancel()
            receivedB.cancel()
            scope.cancel()
        }
    }

    private fun listener(eventLog: SseEventLogRepository, eventBus: SseEventBus) =
        SseEventLogListener(
            connectionFactory = {
                java.sql.DriverManager.getConnection(postgres.jdbcUrl, postgres.username, postgres.password)
            },
            eventLog = eventLog,
            eventBus = eventBus,
        )
}
