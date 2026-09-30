package no.nav.tpt.infrastructure.kafka

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import kotlinx.coroutines.runBlocking
import no.nav.tpt.infrastructure.gcve.GcveClient
import no.nav.tpt.infrastructure.gcve.GcveSyncService
import no.nav.tpt.infrastructure.gcve.InMemoryGcveRepository
import no.nav.tpt.infrastructure.sse.SseEvent
import no.nav.tpt.infrastructure.sse.SseEventEnvelope
import no.nav.tpt.infrastructure.sse.SseEventPublisher
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
import java.util.concurrent.CopyOnWriteArrayList
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

private class CapturingSseEventPublisher : SseEventPublisher {
    val events = CopyOnWriteArrayList<SseEvent>()

    override suspend fun publish(event: SseEvent): SseEventEnvelope {
        events.add(event)
        return SseEventEnvelope(events.size.toLong(), event)
    }
}

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
    fun `should execute team sync and publish SSE progress events to the event log`() = runBlocking {
        val mockRepo = no.nav.tpt.infrastructure.vulnerability.MockVulnerabilityRepository()
        val mockNaisApi = no.nav.tpt.infrastructure.vulnerability.MockNaisApiServiceForSync()
        val sseEventPublisher = CapturingSseEventPublisher()
        val syncService = no.nav.tpt.infrastructure.vulnerability.VulnerabilityTeamSyncService(
            mockNaisApi,
            mockRepo,
            sseEventPublisher,
        )

        val kafkaConfig = testKafkaConfig(kafkaContainer.bootstrapServers, topic)
        val consumer = TeamSyncConsumer(kafkaConfig, syncService, TEST_POLL_TIMEOUT)
        consumer.start(this)
        awaitCondition(message = "Consumer did not become ready") { consumer.isReady() }

        val producer = testProducer(kafkaContainer.bootstrapServers)
        producer.send(ProducerRecord(topic, KafkaKey.TEAM_SYNC, """{"teamSlug":"team-alpha"}""")).get()
        producer.close()

        try {
            awaitCondition(message = "team_sync was not processed") {
                mockNaisApi.getVulnerabilitiesForTeamCallCount == 1 && sseEventPublisher.events.size == 2
            }
            assertEquals(2, sseEventPublisher.events.size)
            assertIs<SseEvent.TeamSyncStarted>(sseEventPublisher.events[0])
            assertIs<SseEvent.TeamSyncComplete>(sseEventPublisher.events[1])
            assertEquals("team-alpha", (sseEventPublisher.events[1] as SseEvent.TeamSyncComplete).teamSlug)
        } finally {
            consumer.stop()
        }
    }

    @Test
    fun `should ignore non-team_sync messages`() = runBlocking {
        val mockRepo = no.nav.tpt.infrastructure.vulnerability.MockVulnerabilityRepository()
        val mockNaisApi = no.nav.tpt.infrastructure.vulnerability.MockNaisApiServiceForSync()
        val syncService = no.nav.tpt.infrastructure.vulnerability.VulnerabilityTeamSyncService(mockNaisApi, mockRepo)

        val kafkaConfig = testKafkaConfig(kafkaContainer.bootstrapServers, topic)
        val consumer = TeamSyncConsumer(kafkaConfig, syncService, TEST_POLL_TIMEOUT)
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
    fun `should execute GCVE sync and publish completion to the event log`() = runBlocking {
        val gcveRepo = InMemoryGcveRepository()
        val mockClient = HttpClient(MockEngine) {
            engine {
                addHandler { respond("[]", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json")) }
            }
        }
        val gcveClient = GcveClient(mockClient, "http://mock-gcve")
        val gcveSyncService = GcveSyncService(gcveClient, gcveRepo)

        val kafkaConfig = testKafkaConfig(kafkaContainer.bootstrapServers, topic)
        val sseEventPublisher = CapturingSseEventPublisher()

        val consumer = GcveSyncConsumer(kafkaConfig, gcveSyncService, gcveRepo, sseEventPublisher, TEST_POLL_TIMEOUT)
        consumer.start(this)
        awaitCondition(message = "Consumer did not become ready") { consumer.isReady() }

        val producer = testProducer(kafkaContainer.bootstrapServers)
        producer.send(ProducerRecord(topic, KafkaKey.GCVE_SYNC, """{"triggeredAt":"2024-01-01T00:00:00Z"}""")).get()
        producer.close()

        try {
            awaitCondition(message = "GCVE sync timestamp was not set") {
                gcveRepo.getLastSyncTimestamp() != null && sseEventPublisher.events.size == 1
            }
            assertEquals(1, sseEventPublisher.events.size)
            assertIs<SseEvent.GcveSyncComplete>(sseEventPublisher.events.single())
        } finally {
            consumer.stop()
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
        val consumer = GcveSyncConsumer(
            kafkaConfig,
            gcveSyncService,
            gcveRepo,
            CapturingSseEventPublisher(),
            TEST_POLL_TIMEOUT,
        )
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
        }
    }
}
