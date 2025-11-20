package no.nav.appsecguide.infrastructure.cache

interface Cache<K, V> {
    suspend fun get(key: K): V?
    suspend fun put(key: K, value: V)
    suspend fun getOrPut(key: K, provider: suspend () -> V): V
    suspend fun invalidate(key: K)
    suspend fun clear()
}

