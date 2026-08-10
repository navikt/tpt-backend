package no.nav.tpt.infrastructure.kafka

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import kotlinx.coroutines.delay
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
import org.testcontainers.kafka.KafkaContainer
import org.testcontainers.utility.DockerImageName
import java.util.*
import kotlin.test.*

private fun startKafka(): KafkaContainer =
    KafkaContainer(DockerImageName.parse("apache/kafka:4.1.1"))
        .waitingFor(KAFKA_WAIT_STRATEGY)
        .also { it.start() }

private fun testKafkaConfig(bootstrapServers: String, topic: String) = KafkaConfig(
    brokers = bootstrapServers,
    certificatePath = "", privateKeyPath = "", caPath = "",
    credstorePassword = "", keystorePath = "", truststorePath = "",
    topic = topic,
)

private fun testProducer(bootstrapServers: String): KafkaProducer<String, String> {
    val props = Properties().apply {
        put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers)
        put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer::class.java.name)
        put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer::class.java.name)
        put(ProducerConfig.ACKS_CONFIG, "all")
    }
    return KafkaProducer(props)
}

// ---------------------------------------------------------------------------

class TeamSyncConsumerIntegrationTest {

    private lateinit var kafkaContainer: KafkaContainer
    private val topic = "test-sync-topic"

    @BeforeTest
    fun setup() {
        kafkaContainer = startKafka()
    }

    @AfterTest
    fun teardown() {
        kafkaContainer.stop()
    }

    @Test
    fun `should execute team sync and publish team_sync_complete to Kafka on team_sync message`() = runBlocking {
        val mockRepo = no.nav.tpt.infrastructure.vulnerability.MockVulnerabilityRepository()
        val mockNaisApi = no.nav.tpt.infrastructure.vulnerability.MockNaisApiServiceForSync()
        val syncService = no.nav.tpt.infrastructure.vulnerability.VulnerabilityTeamSyncService(mockNaisApi, mockRepo)

        val kafkaConfig = testKafkaConfig(kafkaContainer.bootstrapServers, topic)
        val kafkaProducerService = KafkaProducerService(kafkaConfig)

        val receivedKeys = mutableListOf<String>()
        val spyConsumer = object : KafkaConsumerService(kafkaConfig, groupId = "tpt-backend-test-spy", autoCommit = true) {
            override suspend fun processRecord(record: ConsumerRecord<String, String>) {
                receivedKeys.add(record.key())
            }
        }
        spyConsumer.start(this)
        delay(500)

        val consumer = TeamSyncConsumer(kafkaConfig, syncService, kafkaProducerService)
        consumer.start(this)
        delay(1000)

        val producer = testProducer(kafkaContainer.bootstrapServers)
        producer.send(ProducerRecord(topic, "team_sync", """{"teamSlug":"team-alpha"}""")).get()
        producer.close()

        delay(3000)
        consumer.stop()
        spyConsumer.stop()
        kafkaProducerService.close()

        assertEquals(1, mockNaisApi.getVulnerabilitiesForTeamCallCount)
        assertTrue(receivedKeys.contains("team_sync_complete"), "Expected team_sync_complete to be published to Kafka")
    }

    @Test
    fun `should ignore non-team_sync messages`() = runBlocking {
        val mockRepo = no.nav.tpt.infrastructure.vulnerability.MockVulnerabilityRepository()
        val mockNaisApi = no.nav.tpt.infrastructure.vulnerability.MockNaisApiServiceForSync()
        val syncService = no.nav.tpt.infrastructure.vulnerability.VulnerabilityTeamSyncService(mockNaisApi, mockRepo)

        val kafkaConfig = testKafkaConfig(kafkaContainer.bootstrapServers, topic)
        val kafkaProducerService = KafkaProducerService(kafkaConfig)
        val consumer = TeamSyncConsumer(kafkaConfig, syncService, kafkaProducerService)
        consumer.start(this)
        delay(1000)

        val producer = testProducer(kafkaContainer.bootstrapServers)
        producer.send(ProducerRecord(topic, "vuln_data_sync", """{"triggeredAt":"2024-01-01T00:00:00Z"}""")).get()
        producer.send(ProducerRecord(topic, "some-other-key", "irrelevant")).get()
        producer.close()

        delay(3000)
        consumer.stop()
        kafkaProducerService.close()

        assertEquals(0, mockNaisApi.getVulnerabilitiesForTeamCallCount)
    }
}

// ---------------------------------------------------------------------------

class VulnerabilityDataSyncConsumerIntegrationTest {

    private lateinit var kafkaContainer: KafkaContainer
    private val topic = "test-vuln-sync-topic"

    @BeforeTest
    fun setup() {
        kafkaContainer = startKafka()
    }

    @AfterTest
    fun teardown() {
        kafkaContainer.stop()
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
        val consumer = VulnerabilityDataSyncConsumer(kafkaConfig, syncJob)
        consumer.start(this)
        delay(1000)

        val producer = testProducer(kafkaContainer.bootstrapServers)
        producer.send(ProducerRecord(topic, "vuln_data_sync", """{"triggeredAt":"2024-01-01T00:00:00Z"}""")).get()
        producer.close()

        delay(3000)
        consumer.stop()

        assertTrue(mockNaisApi.getAllTeamsCalled)
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
        val consumer = VulnerabilityDataSyncConsumer(kafkaConfig, syncJob)
        consumer.start(this)
        delay(1000)

        val producer = testProducer(kafkaContainer.bootstrapServers)
        producer.send(ProducerRecord(topic, "team_sync", """{"teamSlug":"team-a"}""")).get()
        producer.send(ProducerRecord(topic, "gcve_sync", """{"triggeredAt":"2024-01-01T00:00:00Z"}""")).get()
        producer.close()

        delay(3000)
        consumer.stop()

        assertFalse(mockNaisApi.getAllTeamsCalled)
    }
}

// ---------------------------------------------------------------------------

class GcveSyncConsumerIntegrationTest {

    private lateinit var kafkaContainer: KafkaContainer
    private val topic = "test-gcve-sync-topic"

    @BeforeTest
    fun setup() {
        kafkaContainer = startKafka()
    }

    @AfterTest
    fun teardown() {
        kafkaContainer.stop()
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
        val spyConsumer = object : KafkaConsumerService(kafkaConfig, groupId = "tpt-backend-gcve-test-spy", autoCommit = true) {
            override suspend fun processRecord(record: ConsumerRecord<String, String>) {
                receivedKeys.add(record.key())
            }
        }
        spyConsumer.start(this)
        delay(500)

        val consumer = GcveSyncConsumer(kafkaConfig, gcveSyncService, gcveRepo, kafkaProducerService)
        consumer.start(this)
        delay(1000)

        val producer = testProducer(kafkaContainer.bootstrapServers)
        producer.send(ProducerRecord(topic, "gcve_sync", """{"triggeredAt":"2024-01-01T00:00:00Z"}""")).get()
        producer.close()

        delay(3000)
        consumer.stop()
        spyConsumer.stop()
        kafkaProducerService.close()

        assertNotNull(gcveRepo.getLastSyncTimestamp(), "Sync timestamp should be set after successful sync")
        assertTrue(receivedKeys.contains("gcve_sync_complete"), "Expected gcve_sync_complete to be published to Kafka")
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
        val consumer = GcveSyncConsumer(kafkaConfig, gcveSyncService, gcveRepo, kafkaProducerService)
        consumer.start(this)
        delay(1000)

        val producer = testProducer(kafkaContainer.bootstrapServers)
        producer.send(ProducerRecord(topic, "team_sync", """{"teamSlug":"team-a"}""")).get()
        producer.close()

        delay(3000)
        consumer.stop()
        kafkaProducerService.close()

        assertNull(gcveRepo.getLastSyncTimestamp(), "Sync timestamp should not be set when no gcve_sync received")
    }
}

// ---------------------------------------------------------------------------

class SseFanoutConsumerIntegrationTest {

    private lateinit var kafkaContainer: KafkaContainer
    private val topic = "test-sse-fanout-topic"

    @BeforeTest
    fun setup() {
        kafkaContainer = startKafka()
    }

    @AfterTest
    fun teardown() {
        kafkaContainer.stop()
    }

    @Test
    fun `should emit TeamSyncStarted SSE event on team_sync_started message`() = runBlocking {
        val eventBus = SseEventBus()
        val receivedEvents = mutableListOf<SseEvent>()
        val collectJob = launch { eventBus.events.collect { receivedEvents.add(it) } }

        val kafkaConfig = testKafkaConfig(kafkaContainer.bootstrapServers, topic)
        val consumer = SseFanoutConsumer(kafkaConfig, eventBus)
        consumer.start(this)
        delay(1000)

        val producer = testProducer(kafkaContainer.bootstrapServers)
        producer.send(ProducerRecord(topic, "team_sync_started", """{"teamSlug":"team-gamma","timestamp":"2024-01-01T00:00:00Z"}""")).get()
        producer.close()

        delay(3000)
        consumer.stop()
        collectJob.cancel()

        assertEquals(1, receivedEvents.size)
        val event = receivedEvents[0]
        assertIs<SseEvent.TeamSyncStarted>(event)
        assertEquals("team-gamma", event.teamSlug)
    }

    @Test
    fun `should emit TeamSyncComplete SSE event on team_sync_complete message`() = runBlocking {
        val eventBus = SseEventBus()
        val receivedEvents = mutableListOf<SseEvent>()
        val collectJob = launch { eventBus.events.collect { receivedEvents.add(it) } }

        val kafkaConfig = testKafkaConfig(kafkaContainer.bootstrapServers, topic)
        val consumer = SseFanoutConsumer(kafkaConfig, eventBus)
        consumer.start(this)
        delay(1000)

        val producer = testProducer(kafkaContainer.bootstrapServers)
        producer.send(ProducerRecord(topic, "team_sync_complete", """{"teamSlug":"team-beta"}""")).get()
        producer.close()

        delay(3000)
        consumer.stop()
        collectJob.cancel()

        assertEquals(1, receivedEvents.size)
        val event = receivedEvents[0]
        assertIs<SseEvent.TeamSyncComplete>(event)
        assertEquals("team-beta", event.teamSlug)
    }

    @Test
    fun `should emit GcveSyncComplete SSE event on gcve_sync_complete message`() = runBlocking {
        val eventBus = SseEventBus()
        val receivedEvents = mutableListOf<SseEvent>()
        val collectJob = launch { eventBus.events.collect { receivedEvents.add(it) } }

        val kafkaConfig = testKafkaConfig(kafkaContainer.bootstrapServers, topic)
        val consumer = SseFanoutConsumer(kafkaConfig, eventBus)
        consumer.start(this)
        delay(1000)

        val producer = testProducer(kafkaContainer.bootstrapServers)
        producer.send(ProducerRecord(topic, "gcve_sync_complete", """{"cveCount":42}""")).get()
        producer.close()

        delay(3000)
        consumer.stop()
        collectJob.cancel()

        assertEquals(1, receivedEvents.size)
        val event = receivedEvents[0]
        assertIs<SseEvent.GcveSyncComplete>(event)
        assertEquals(42, event.cveCount)
    }

    @Test
    fun `should ignore non-SSE messages`() = runBlocking {
        val eventBus = SseEventBus()
        val receivedEvents = mutableListOf<SseEvent>()
        val collectJob = launch { eventBus.events.collect { receivedEvents.add(it) } }

        val kafkaConfig = testKafkaConfig(kafkaContainer.bootstrapServers, topic)
        val consumer = SseFanoutConsumer(kafkaConfig, eventBus)
        consumer.start(this)
        delay(1000)

        val producer = testProducer(kafkaContainer.bootstrapServers)
        producer.send(ProducerRecord(topic, "team_sync", """{"teamSlug":"team-a"}""")).get()
        producer.send(ProducerRecord(topic, "gcve_sync", """{"triggeredAt":"2024-01-01T00:00:00Z"}""")).get()
        producer.send(ProducerRecord(topic, "vuln_data_sync", """{"triggeredAt":"2024-01-01T00:00:00Z"}""")).get()
        producer.close()

        delay(3000)
        consumer.stop()
        collectJob.cancel()

        assertEquals(0, receivedEvents.size)
    }
}
