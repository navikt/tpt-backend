package no.nav.tpt.infrastructure.kafka

import kotlin.test.Test
import kotlin.test.assertNull

class KafkaConfigTest {

    @Test
    fun `should return null when Kafka environment variables are not set`() {
        val config = KafkaConfig.fromEnvironment()
        assertNull(config)
    }
}

