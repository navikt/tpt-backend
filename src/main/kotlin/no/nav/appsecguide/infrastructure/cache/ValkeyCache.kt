package no.nav.appsecguide.infrastructure.cache

import io.valkey.DefaultJedisClientConfig
import io.valkey.HostAndPort
import io.valkey.JedisPool as ValkeyPool
import io.valkey.JedisPoolConfig as ValkeyPoolConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import kotlin.time.Duration

class ValkeyCache<K, V>(
    private val pool: ValkeyPool,
    private val ttl: Duration,
    private val keyPrefix: String,
    private val valueSerializer: KSerializer<V>
) : Cache<K, V> {
    private val json = Json { ignoreUnknownKeys = true }
    private val logger = LoggerFactory.getLogger(ValkeyCache::class.java)

    override suspend fun get(key: K): V? = withContext(Dispatchers.IO) {
        try {
            pool.resource.use { client ->
                val redisKey = "$keyPrefix:$key"
                val value = client.get(redisKey) ?: return@withContext null
                json.decodeFromString(valueSerializer, value)
            }
        } catch (e: Exception) {
            logger.error("Failed to get from cache: $key", e)
            null
        }
    }

    override suspend fun put(key: K, value: V): Unit = withContext(Dispatchers.IO) {
        try {
            pool.resource.use { client ->
                val redisKey = "$keyPrefix:$key"
                val serialized = json.encodeToString(valueSerializer, value)
                client.setex(redisKey, ttl.inWholeSeconds, serialized)
            }
        } catch (e: Exception) {
            logger.error("Failed to put to cache: $key", e)
        }
    }

    override suspend fun getOrPut(key: K, provider: suspend () -> V): V {
        get(key)?.let { return it }

        val value = provider()
        put(key, value)
        return value
    }

    override suspend fun invalidate(key: K): Unit = withContext(Dispatchers.IO) {
        try {
            pool.resource.use { client ->
                val redisKey = "$keyPrefix:$key"
                client.del(redisKey)
            }
        } catch (e: Exception) {
            logger.error("Failed to invalidate cache: $key", e)
        }
    }

    override suspend fun clear(): Unit = withContext(Dispatchers.IO) {
        try {
            pool.resource.use { client ->
                val pattern = "$keyPrefix:*"
                val keys = client.keys(pattern)
                if (keys.isNotEmpty()) {
                    client.del(*keys.toTypedArray())
                }
            }
        } catch (e: Exception) {
            logger.error("Failed to clear cache with prefix: $keyPrefix", e)
        }
    }

    fun close() {
        pool.close()
    }
}

object ValkeyClientFactory {
    private val logger = LoggerFactory.getLogger(ValkeyClientFactory::class.java)

    fun createPool(
        host: String,
        port: Int,
        userName: String,
        password: String
    ): ValkeyPool {
        logger.info("Connecting to Valkey at $host:$port as user $userName")

        val hostAndPort = HostAndPort(host, port)
        val config = DefaultJedisClientConfig.builder()
            .user(userName)
            .password(password)
            .ssl(true)
            .build()

        val poolConfig = ValkeyPoolConfig().apply {
            maxTotal = 20
            maxIdle = 10
            minIdle = 5
        }

        return ValkeyPool(poolConfig, hostAndPort, config)
    }
}

