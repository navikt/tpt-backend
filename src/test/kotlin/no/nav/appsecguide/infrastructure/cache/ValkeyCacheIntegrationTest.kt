package no.nav.appsecguide.infrastructure.cache

import kotlinx.coroutines.test.runTest
import kotlinx.serialization.Serializable
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.testcontainers.containers.GenericContainer
import org.testcontainers.utility.DockerImageName
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.seconds

@Serializable
data class TestData(val id: String, val value: String)

class ValkeyCacheIntegrationTest {

    companion object {
        private lateinit var valkeyContainer: GenericContainer<*>
        private lateinit var cache: ValkeyCache<String, TestData>

        @JvmStatic
        @BeforeAll
        fun setup() {
            valkeyContainer = GenericContainer(DockerImageName.parse("ghcr.io/valkey-io/valkey:7.2-alpine"))
                .withExposedPorts(6379)
            valkeyContainer.start()

            val host = valkeyContainer.host
            val port = valkeyContainer.getMappedPort(6379)
            val valkeyUri = "redis://$host:$port"

            val pool = createTestValkeyPool(valkeyUri)
            cache = ValkeyCache(
                pool = pool,
                ttl = 10.seconds,
                keyPrefix = "test",
                valueSerializer = TestData.serializer()
            )
        }

        private fun createTestValkeyPool(uri: String): io.valkey.JedisPool {
            val valkeyUri = java.net.URI.create(uri)
            val poolConfig = io.valkey.JedisPoolConfig().apply {
                maxTotal = 20
                maxIdle = 10
                minIdle = 5
            }
            return io.valkey.JedisPool(poolConfig, valkeyUri)
        }

        @JvmStatic
        @AfterAll
        fun teardown() {
            cache.close()
            valkeyContainer.stop()
        }
    }

    @Test
    fun `should store and retrieve value from Valkey`() = runTest {
        val key = "test-key-1"
        val data = TestData("1", "test value")

        cache.put(key, data)
        val retrieved = cache.get(key)

        assertNotNull(retrieved)
        assertEquals(data.id, retrieved.id)
        assertEquals(data.value, retrieved.value)
    }

    @Test
    fun `should return null for non-existent key`() = runTest {
        val retrieved = cache.get("non-existent-key")
        assertNull(retrieved)
    }

    @Test
    fun `should use getOrPut to cache value on first call`() = runTest {
        val key = "test-key-2"
        var providerCallCount = 0

        val data1 = cache.getOrPut(key) {
            providerCallCount++
            TestData("2", "cached value")
        }

        val data2 = cache.getOrPut(key) {
            providerCallCount++
            TestData("2", "should not be used")
        }

        assertEquals(1, providerCallCount)
        assertEquals(data1.value, data2.value)
        assertEquals("cached value", data2.value)
    }

    @Test
    fun `should invalidate specific key`() = runTest {
        val key = "test-key-3"
        val data = TestData("3", "to be invalidated")

        cache.put(key, data)
        assertNotNull(cache.get(key))

        cache.invalidate(key)
        assertNull(cache.get(key))
    }

    @Test
    fun `should clear all keys with prefix`() = runTest {
        cache.put("clear-test-1", TestData("4", "value 1"))
        cache.put("clear-test-2", TestData("5", "value 2"))

        assertNotNull(cache.get("clear-test-1"))
        assertNotNull(cache.get("clear-test-2"))

        cache.clear()

        assertNull(cache.get("clear-test-1"))
        assertNull(cache.get("clear-test-2"))
    }

    @Test
    fun `should handle special characters in keys`() = runTest {
        val key = "test:key:with:colons"
        val data = TestData("6", "special chars")

        cache.put(key, data)
        val retrieved = cache.get(key)

        assertNotNull(retrieved)
        assertEquals(data.value, retrieved.value)
    }
}

