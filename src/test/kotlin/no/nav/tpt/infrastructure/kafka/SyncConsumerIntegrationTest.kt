package no.nav.tpt.infrastructure.kafka

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import no.nav.tpt.infrastructure.gcve.GcveClient
import no.nav.tpt.infrastructure.gcve.GcveSyncService
import no.nav.tpt.infrastructure.gcve.InMemoryGcveRepository
import no.nav.tpt.infrastructure.sse.SseEvent
import no.nav.tpt.infrastructure.sse.SseEventBus
import no.nav.tpt.plugins.KAFKA_WAIT_STRATEGY
import org.apache.kafka.clients.consumer.ConsumerRecord
import org.apache.kafka.clients.producer.KafkaProducer
import org.apache.kafka.clients.producer.ProducerConfig
import org.apache.kafka.clients.producer.ProducerRecord
import org.apache.kafka.common.serialization.StringSerializer
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import org.testcontainers.kafka.KafkaContainer
import org.testcontainers.utility.DockerImageName
import java.util.*
import kotlin.test.*

private fun testProducer(bootstrapServers: String): KafkaProducer<String, String> =
    KafkaProducer(
        Properties().apply {
            put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers)
            put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer::class.java.name)
            put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer::class.java.name)
            put(ProducerConfig.ACKS_CONFIG, "all")
        }
    )

private fun testKafkaConfig(bootstrapServers: String, topic: String) = KafkaConfig(
    brokers = bootstrapServers,
    certificatePath = "", privateKeyPath = "", caPath = "",
    credstorePassword = "", keystorePath = "", truststorePath = "",
    topic = topic,
)

// ---------------------------------------------------------------------------

@Testcontainers
class TeamSyncConsumerIntegrationTest {

    companion object {
        @Container
        private val kafkaContainer = KafkaContainer(DockerImageName.parse("apache/kafka:4.1.1"))
            .waitingFor(KAFKA_WAIT_STRATEGY)
    }

    private lateinit var topic: String

    @BeforeEach
    fun setup() {
        topic = "test-sync-topic-${UUID.randomUUID()}"
    }

    @Test
    fun `should execute team sync and publish team_sync_complete to Kafka on team_sync message`() = runBlocking {
        val mockRepo = no.nav.tpt.infrastructure.vulnerability.MockVulnerabilityRepository()
        val mockNaisApi = no.nav.tpt.infrastructure.vulnerability.MockNaisApiServiceForSync()
        val syncService = no.nav.tpt.infrastructure.vulnerability.VulnerabilityTeamSyncService(mockNaisApi, mockRepo)

        val kafkaConfig = testKafkaConfig(kafkaContainer.bootstrapServers, topic)
        val kafkaProducerService = KafkaProducerService(kafkaConfig)

        val receivedKeys = mutableListOf<String>()
        val spyConsumer = object : KafkaConsumerService(kafkaConfig, groupId = "tpt-backend-test-spy", autoCommit = true, pollTimeout = TEST_POLL_TIMEOUT) {
            override suspend fun processRecord(record: ConsumerRecord<String, String>) {
                receivedKeys.add(record.key())
            }
        }
        spyConsumer.start(this)

        val consumer = TeamSyncConsumer(kafkaConfig, syncService, kafkaProducerService, TEST_POLL_TIMEOUT)
        consumer.start(this)
        awaitCondition(message = "Consumer did not become ready") { consumer.isReady() }

        val producer = testProducer(kafkaContainer.bootstrapServers)
        producer.send(ProducerRecord(topic, KafkaKey.TEAM_SYNC, """{"teamSlug":"team-alpha"}""")).get()
        producer.close()

        try {
            awaitCondition(message = "team_sync was not processed") {
                mockNaisApi.getVulnerabilitiesForTeamCallCount == 1
            }
            awaitCondition(message = "team_sync_complete was not published to Kafka") {
                receivedKeys.contains(KafkaKey.TEAM_SYNC_COMPLETE)
            }
        } finally {
            consumer.stop()
            spyConsumer.stop()
            kafkaProducerService.close()
        }
    }

    @Test
    fun `should ignore non-team_sync messages`() = runBlocking {
        val mockRepo = no.nav.tpt.infrastructure.vulnerability.MockVulnerabilityRepository()
        val mockNaisApi = no.nav.tpt.infrastructure.vulnerability.MockNaisApiServiceForSync()
        val syncService = no.nav.tpt.infrastructure.vulnerability.VulnerabilityTeamSyncService(mockNaisApi, mockRepo)

        val kafkaConfig = testKafkaConfig(kafkaContainer.bootstrapServers, topic)
        val kafkaProducerService = KafkaProducerService(kafkaConfig)
        val consumer = TeamSyncConsumer(kafkaConfig, syncService, kafkaProducerService, TEST_POLL_TIMEOUT)
        consumer.start(this)
        awaitCondition(message = "Consumer did not become ready") { consumer.isReady() }

        val producer = testProducer(kafkaContainer.bootstrapServers)
        producer.send(ProducerRecord(topic, KafkaKey.VULN_DATA_SYNC, """{"triggeredAt":"2024-01-01T00:00:00Z"}""")).get()
        producer.send(ProducerRecord(topic, "some-other-key", "irrelevant")).get()
        producer.close()

        try {
            awaitCondition(message = "Consumer did not become ready") { consumer.isReady() }
            assertEquals(0, mockNaisApi.getVulnerabilitiesForTeamCallCount)
        } finally {
            consumer.stop()
            kafkaProducerService.close()
        }
    }
}

// ---------------------------------------------------------------------------

@Testcontainers
class VulnerabilityDataSyncConsumerIntegrationTest {

    companion object {
        @Container
        private val kafkaContainer = KafkaContainer(DockerImageName.parse("apache/kafka:4.1.1"))
            .waitingFor(KAFKA_WAIT_STRATEGY)
    }

    private lateinit var topic: String

    @BeforeEach
    fun setup() {
        topic = "test-vuln-sync-topic-${UUID.randomUUID()}"
    }

    @Test
    fun `should execute full sync on vuln_data_sync message`() = runBlocking {
        val mockRepo = no.nav.tpt.infrastructure.vulnerability.MockVulnerabilityRepository()
        val mockNaisApi = no.nav.tpt.infrastructure.vulnerability.MockNaisApiServiceForSync(
            teams = listOf(no.nav.tpt.infrastructure.nais.TeamInfo("team-a", "#team-a"))
        )
        val syncService = no.nav.tpt.infrastructure.vulnerability.VulnerabilityTeamSyncService(mockNaisApi, mockRepo)
        val adminRepo = no.nav.tpt.infrastructure.admin.InMemoryAdminReportRepository()
        val syncJob = no.nav.tpt.infrastructure.vulnerability.VulnerabilityDataSyncJob(
            naisApiService = mockNaisApi,
            vulnerabilityTeamSyncService = syncService,
            vulnerabilityRepository = mockRepo,
            adminReportRepository = adminRepo,
            teamDelayMs = 0,
        )

        val kafkaConfig = testKafkaConfig(kafkaContainer.bootstrapServers, topic)
        val consumer = VulnerabilityDataSyncConsumer(kafkaConfig, syncJob, TEST_POLL_TIMEOUT)
        consumer.start(this)
        awaitCondition(message = "Consumer did not become ready") { consumer.isReady() }

        val producer = testProducer(kafkaContainer.bootstrapServers)
        producer.send(ProducerRecord(topic, KafkaKey.VULN_DATA_SYNC, """{"triggeredAt":"2024-01-01T00:00:00Z"}""")).get()
        producer.close()

        try {
            awaitCondition(message = "Full sync was not triggered") { mockNaisApi.getAllTeamsCalled }
        } finally {
            consumer.stop()
        }
    }

    @Test
    fun `should ignore non-vuln_data_sync messages`() = runBlocking {
        val mockRepo = no.nav.tpt.infrastructure.vulnerability.MockVulnerabilityRepository()
        val mockNaisApi = no.nav.tpt.infrastructure.vulnerability.MockNaisApiServiceForSync()
        val syncService = no.nav.tpt.infrastructure.vulnerability.VulnerabilityTeamSyncService(mockNaisApi, mockRepo)
        val syncJob = no.nav.tpt.infrastructure.vulnerability.VulnerabilityDataSyncJob(
            naisApiService = mockNaisApi,
            vulnerabilityTeamSyncService = syncService,
            vulnerabilityRepository = mockRepo,
            adminReportRepository = no.nav.tpt.infrastructure.admin.InMemoryAdminReportRepository(),
            teamDelayMs = 0,
        )

        val kafkaConfig = testKafkaConfig(kafkaContainer.bootstrapServers, topic)
        val consumer = VulnerabilityDataSyncConsumer(kafkaConfig, syncJob, TEST_POLL_TIMEOUT)
        consumer.start(this)
        awaitCondition(message = "Consumer did not become ready") { consumer.isReady() }

        val producer = testProducer(kafkaContainer.bootstrapServers)
        producer.send(ProducerRecord(topic, KafkaKey.TEAM_SYNC, """{"teamSlug":"team-a"}""")).get()
        producer.send(ProducerRecord(topic, KafkaKey.GCVE_SYNC, """{"triggeredAt":"2024-01-01T00:00:00Z"}""")).get()
        producer.close()

        try {
            awaitCondition(message = "Consumer did not become ready") { consumer.isReady() }
            assertFalse(mockNaisApi.getAllTeamsCalled)
        } finally {
            consumer.stop()
        }
    }
}

// ---------------------------------------------------------------------------

@Testcontainers
class GcveSyncConsumerIntegrationTest {

    companion object {
        @Container
        private val kafkaContainer = KafkaContainer(DockerImageName.parse("apache/kafka:4.1.1"))
            .waitingFor(KAFKA_WAIT_STRATEGY)
    }

    private lateinit var topic: String

    @BeforeEach
    fun setup() {
        topic = "test-gcve-sync-topic-${UUID.randomUUID()}"
    }

    @Test
    fun `should execute GCVE sync and publish gcve_sync_complete to Kafka on gcve_sync message`() = runBlocking {
        val gcveRepo = InMemoryGcveRepository()
        val mockClient = HttpClient(MockEngine) {
            engine {
                addHandler { respond("[]", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json")) }
            }
        }
        val gcveClient = GcveClient(mockClient, "http://mock-gcve")
        val gcveSyncService = GcveSyncService(gcveClient, gcveRepo)

        val kafkaConfig = testKafkaConfig(kafkaContainer.bootstrapServers, topic)
        val kafkaProducerService = KafkaProducerService(kafkaConfig)

        val receivedKeys = mutableListOf<String>()
        val spyConsumer = object : KafkaConsumerService(kafkaConfig, groupId = "tpt-backend-gcve-test-spy", autoCommit = true, pollTimeout = TEST_POLL_TIMEOUT) {
            override suspend fun processRecord(record: ConsumerRecord<String, String>) {
                receivedKeys.add(record.key())
            }
        }
        spyConsumer.start(this)

        val consumer = GcveSyncConsumer(kafkaConfig, gcveSyncService, gcveRepo, kafkaProducerService, TEST_POLL_TIMEOUT)
        consumer.start(this)
        awaitCondition(message = "Consumer did not become ready") { consumer.isReady() }

        val producer = testProducer(kafkaContainer.bootstrapServers)
        producer.send(ProducerRecord(topic, KafkaKey.GCVE_SYNC, """{"triggeredAt":"2024-01-01T00:00:00Z"}""")).get()
        producer.close()

        try {
            awaitCondition(message = "GCVE sync timestamp was not set") {
                gcveRepo.getLastSyncTimestamp() != null
            }
            awaitCondition(message = "gcve_sync_complete was not published to Kafka") {
                receivedKeys.contains(KafkaKey.GCVE_SYNC_COMPLETE)
            }
        } finally {
            consumer.stop()
            spyConsumer.stop()
            kafkaProducerService.close()
        }
    }

    @Test
    fun `should ignore non-gcve_sync messages`() = runBlocking {
        val gcveRepo = InMemoryGcveRepository()
        val mockClient = HttpClient(MockEngine) {
            engine { addHandler { respond("[]", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json")) } }
        }
        val gcveSyncService = GcveSyncService(GcveClient(mockClient, "http://mock-gcve"), gcveRepo)

        val kafkaConfig = testKafkaConfig(kafkaContainer.bootstrapServers, topic)
        val kafkaProducerService = KafkaProducerService(kafkaConfig)
        val consumer = GcveSyncConsumer(kafkaConfig, gcveSyncService, gcveRepo, kafkaProducerService, TEST_POLL_TIMEOUT)
        consumer.start(this)
        awaitCondition(message = "Consumer did not become ready") { consumer.isReady() }

        val producer = testProducer(kafkaContainer.bootstrapServers)
        producer.send(ProducerRecord(topic, KafkaKey.TEAM_SYNC, """{"teamSlug":"team-a"}""")).get()
        producer.close()

        try {
            awaitCondition(message = "Consumer did not become ready") { consumer.isReady() }
            assertNull(gcveRepo.getLastSyncTimestamp(), "Sync timestamp should not be set when no gcve_sync received")
        } finally {
            consumer.stop()
            kafkaProducerService.close()
        }
    }
}

// ---------------------------------------------------------------------------

@Testcontainers
class SseFanoutConsumerIntegrationTest {

    companion object {
        @Container
        private val kafkaContainer = KafkaContainer(DockerImageName.parse("apache/kafka:4.1.1"))
            .waitingFor(KAFKA_WAIT_STRATEGY)
    }

    private lateinit var topic: String

    @BeforeEach
    fun setup() {
        topic = "test-sse-fanout-topic-${UUID.randomUUID()}"
    }

    @Test
    fun `should emit TeamSyncStarted SSE event on team_sync_started message`() = runBlocking {
        val eventBus = SseEventBus()
        val receivedEvents = mutableListOf<SseEvent>()
        val collectJob = launch { eventBus.events.collect { receivedEvents.add(it) } }

        val kafkaConfig = testKafkaConfig(kafkaContainer.bootstrapServers, topic)
        val consumer = SseFanoutConsumer(kafkaConfig, eventBus, TEST_POLL_TIMEOUT)
        consumer.start(this)
        awaitCondition(message = "Consumer did not become ready") { consumer.isReady() }

        val producer = testProducer(kafkaContainer.bootstrapServers)
        producer.send(ProducerRecord(topic, KafkaKey.TEAM_SYNC_STARTED, """{"teamSlug":"team-gamma","timestamp":"2024-01-01T00:00:00Z"}""")).get()
        producer.close()

        try {
            awaitCondition(message = "TeamSyncStarted SSE event was not emitted") { receivedEvents.size == 1 }
            val event = receivedEvents[0]
            assertIs<SseEvent.TeamSyncStarted>(event)
            assertEquals("team-gamma", event.teamSlug)
        } finally {
            consumer.stop()
            collectJob.cancel()
        }
    }

    @Test
    fun `should emit TeamSyncComplete SSE event on team_sync_complete message`() = runBlocking {
        val eventBus = SseEventBus()
        val receivedEvents = mutableListOf<SseEvent>()
        val collectJob = launch { eventBus.events.collect { receivedEvents.add(it) } }

        val kafkaConfig = testKafkaConfig(kafkaContainer.bootstrapServers, topic)
        val consumer = SseFanoutConsumer(kafkaConfig, eventBus, TEST_POLL_TIMEOUT)
        consumer.start(this)
        awaitCondition(message = "Consumer did not become ready") { consumer.isReady() }

        val producer = testProducer(kafkaContainer.bootstrapServers)
        producer.send(ProducerRecord(topic, KafkaKey.TEAM_SYNC_COMPLETE, """{"teamSlug":"team-beta"}""")).get()
        producer.close()

        try {
            awaitCondition(message = "TeamSyncComplete SSE event was not emitted") { receivedEvents.size == 1 }
            val event = receivedEvents[0]
            assertIs<SseEvent.TeamSyncComplete>(event)
            assertEquals("team-beta", event.teamSlug)
        } finally {
            consumer.stop()
            collectJob.cancel()
        }
    }

    @Test
    fun `should emit GcveSyncComplete SSE event on gcve_sync_complete message`() = runBlocking {
        val eventBus = SseEventBus()
        val receivedEvents = mutableListOf<SseEvent>()
        val collectJob = launch { eventBus.events.collect { receivedEvents.add(it) } }

        val kafkaConfig = testKafkaConfig(kafkaContainer.bootstrapServers, topic)
        val consumer = SseFanoutConsumer(kafkaConfig, eventBus, TEST_POLL_TIMEOUT)
        consumer.start(this)
        awaitCondition(message = "Consumer did not become ready") { consumer.isReady() }

        val producer = testProducer(kafkaContainer.bootstrapServers)
        producer.send(ProducerRecord(topic, KafkaKey.GCVE_SYNC_COMPLETE, """{"cveCount":42}""")).get()
        producer.close()

        try {
            awaitCondition(message = "GcveSyncComplete SSE event was not emitted") { receivedEvents.size == 1 }
            val event = receivedEvents[0]
            assertIs<SseEvent.GcveSyncComplete>(event)
            assertEquals(42, event.cveCount)
        } finally {
            consumer.stop()
            collectJob.cancel()
        }
    }

    @Test
    fun `should ignore non-SSE messages`() = runBlocking {
        val eventBus = SseEventBus()
        val receivedEvents = mutableListOf<SseEvent>()
        val collectJob = launch { eventBus.events.collect { receivedEvents.add(it) } }

        val kafkaConfig = testKafkaConfig(kafkaContainer.bootstrapServers, topic)
        val consumer = SseFanoutConsumer(kafkaConfig, eventBus, TEST_POLL_TIMEOUT)
        consumer.start(this)
        awaitCondition(message = "Consumer did not become ready") { consumer.isReady() }

        val producer = testProducer(kafkaContainer.bootstrapServers)
        producer.send(ProducerRecord(topic, KafkaKey.TEAM_SYNC, """{"teamSlug":"team-a"}""")).get()
        producer.send(ProducerRecord(topic, KafkaKey.GCVE_SYNC, """{"triggeredAt":"2024-01-01T00:00:00Z"}""")).get()
        producer.send(ProducerRecord(topic, KafkaKey.VULN_DATA_SYNC, """{"triggeredAt":"2024-01-01T00:00:00Z"}""")).get()
        producer.close()

        try {
            awaitCondition(message = "Consumer did not become ready") { consumer.isReady() }
            assertEquals(0, receivedEvents.size)
        } finally {
            consumer.stop()
            collectJob.cancel()
        }
    }
}
