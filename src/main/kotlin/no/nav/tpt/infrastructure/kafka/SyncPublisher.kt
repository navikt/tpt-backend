package no.nav.tpt.infrastructure.kafka

interface SyncPublisher {
    fun publish(key: String, value: String)
}
