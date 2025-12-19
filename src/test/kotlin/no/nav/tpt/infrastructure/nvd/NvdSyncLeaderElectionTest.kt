package no.nav.tpt.infrastructure.nvd

import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import org.jetbrains.exposed.sql.Database
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

@Testcontainers
class NvdSyncLeaderElectionTest {

    companion object {
        @Container
        private val postgresContainer = PostgreSQLContainer<Nothing>("postgres:15-alpine").apply {
            withDatabaseName("test_db")
            withUsername("test")
            withPassword("test")
        }

        private lateinit var database: Database

        @JvmStatic
        @BeforeAll
        fun setUp() {
            postgresContainer.start()
            database = Database.connect(
                url = postgresContainer.jdbcUrl,
                driver = "org.postgresql.Driver",
                user = postgresContainer.username,
                password = postgresContainer.password
            )
        }

        @JvmStatic
        @AfterAll
        fun tearDown() {
            postgresContainer.stop()
        }
    }

    @Test
    fun `should allow only one pod to acquire lock`() = runTest {
        val leaderElection = NvdSyncLeaderElection(database)
        var pod1Executed = false
        var pod2Executed = false

        // Simulate two pods trying to sync simultaneously
        val job1 = async {
            leaderElection.withLeaderLock {
                pod1Executed = true
                delay(100) // Simulate work
            }
        }

        val job2 = async {
            delay(10) // Small delay to ensure pod1 acquires lock first
            leaderElection.withLeaderLock {
                pod2Executed = true
                delay(100) // Simulate work
            }
        }

        job1.await()
        job2.await()

        // Only one pod should have executed
        assert(pod1Executed xor pod2Executed) {
            "Expected exactly one pod to execute, but pod1=$pod1Executed, pod2=$pod2Executed"
        }
    }

    @Test
    fun `should release lock after operation completes`() = runTest {
        val leaderElection = NvdSyncLeaderElection(database)

        // First operation acquires and releases lock
        val result1 = leaderElection.withLeaderLock {
            "first"
        }
        assertNotNull(result1)
        assertEquals("first", result1)

        // Second operation should be able to acquire lock after first releases it
        val result2 = leaderElection.withLeaderLock {
            "second"
        }
        assertNotNull(result2)
        assertEquals("second", result2)
    }

    @Test
    fun `should return null if lock cannot be acquired`() = runTest {
        val leaderElection = NvdSyncLeaderElection(database)

        // Acquire lock
        val job1 = async {
            leaderElection.withLeaderLock {
                delay(500) // Hold lock for a while
                "completed"
            }
        }

        delay(50) // Ensure first job has lock

        // Try to acquire lock while it's held
        val result = leaderElection.withLeaderLock {
            "should not execute"
        }

        assertNull(result, "Should return null when lock is held by another pod")

        job1.await()
    }
}

