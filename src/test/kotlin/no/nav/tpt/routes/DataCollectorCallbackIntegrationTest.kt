package no.nav.tpt.routes

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import no.nav.tpt.infrastructure.auth.IntrospectionResponse
import no.nav.tpt.infrastructure.auth.TokenIntrospectionService
import no.nav.tpt.infrastructure.datacollector.DataCollectorRepositoryImpl
import no.nav.tpt.infrastructure.datacollector.DatacollectorRepository
import no.nav.tpt.infrastructure.github.GitHubRepository
import no.nav.tpt.infrastructure.github.GitHubRepositoryImpl
import no.nav.tpt.infrastructure.kafka.DataCollectorConsumer
import no.nav.tpt.infrastructure.kafka.KafkaConfig
import no.nav.tpt.infrastructure.kafka.KafkaKey
import no.nav.tpt.infrastructure.kafka.TEST_POLL_TIMEOUT
import no.nav.tpt.infrastructure.kafka.awaitCondition
import no.nav.tpt.infrastructure.sse.SseEvent
import no.nav.tpt.infrastructure.sse.SseEventLogRepository
import no.nav.tpt.plugins.KAFKA_WAIT_STRATEGY
import no.nav.tpt.plugins.testModule
import org.apache.kafka.clients.producer.KafkaProducer
import org.apache.kafka.clients.producer.ProducerConfig
import org.apache.kafka.clients.producer.ProducerRecord
import org.apache.kafka.common.serialization.StringSerializer
import org.flywaydb.core.Flyway
import org.jetbrains.exposed.v1.jdbc.Database
import org.junit.jupiter.api.BeforeAll
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import org.testcontainers.kafka.KafkaContainer
import org.testcontainers.utility.DockerImageName
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals

@Testcontainers
class DataCollectorCallbackIntegrationTest {

    companion object {
        @Container
        private val postgresContainer = PostgreSQLContainer<Nothing>("postgres:17-alpine").apply {
            withDatabaseName("test_db")
            withUsername("test")
            withPassword("test")
        }

        @Container
        private val kafkaContainer = KafkaContainer(DockerImageName.parse("apache/kafka:4.1.1"))
            .waitingFor(KAFKA_WAIT_STRATEGY)

        private lateinit var gitHubRepository: GitHubRepository
        private lateinit var dataCollectorRepository: DatacollectorRepository
        private lateinit var sseEventLogRepository: SseEventLogRepository

        @JvmStatic
        @BeforeAll
        fun setUpClass() {
            val dataSource = HikariDataSource(HikariConfig().apply {
                jdbcUrl = postgresContainer.jdbcUrl
                username = postgresContainer.username
                password = postgresContainer.password
                driverClassName = "org.postgresql.Driver"
            })
            Flyway.configure().dataSource(dataSource).locations("classpath:db/migration").load().migrate()

            val database = Database.connect(dataSource)
            gitHubRepository = GitHubRepositoryImpl(database)
            dataCollectorRepository = DataCollectorRepositoryImpl(database)
            sseEventLogRepository = SseEventLogRepository(database)
        }
    }

    private val dataCollectorToken = object : TokenIntrospectionService {
        override suspend fun introspect(token: String) = IntrospectionResponse(
            active = true,
            claims = mapOf(
                "idtyp" to JsonPrimitive("app"),
                "azp_name" to JsonPrimitive("dev-gcp:appsec:tpt-data-collector"),
            ),
        )
    }

    private fun repositoryPayload(nameWithOwner: String) = """
        {
          "nameWithOwner": "$nameWithOwner",
          "naisTeams": ["team-a", "team-b"],
          "unknownField": "ignored",
          "vulnerabilities": [
            {
              "severity": "CRITICAL",
              "identifiers": [
                {"value": "CVE-2024-9999", "type": "CVE"},
                {"value": "GHSA-abcd-efgh-ijkl", "type": "GHSA"}
              ],
              "dependencyScope": "RUNTIME",
              "dependabotUpdatePullRequestUrl": "https://github.com/org/repo/pull/42",
              "publishedAt": "2024-01-15T10:30:00Z",
              "cvssScore": 9.8,
              "summary": "Critical vulnerability in dependency",
              "packageEcosystem": "NPM",
              "packageName": "vulnerable-package"
            },
            {
              "severity": "LOW",
              "identifiers": [{"value": "CVE-2024-1111", "type": "CVE"}]
            }
          ]
        }
    """.trimIndent()

    private fun checksPayload(repoName: String, owner: String) = """
        {
          "repoName": "$repoName",
          "repoOwners": ["$owner"],
          "results": [
            {"type": "AllGood", "name": "branch-protection", "desc": "Branch protection", "severity": "HIGH", "whenChecked": "2026-01-01T10:00:00.123Z"},
            {"type": "NeedsWork", "name": "codeowners", "severity": "LOW", "whenChecked": "2026-01-01T10:00:00Z", "reasons": ["missing file", "no owners"]}
          ]
        }
    """.trimIndent()

    private fun sendViaKafka(key: String, value: String, stored: suspend () -> Boolean) = runBlocking {
        val topic = "callback-comparison-topic"
        val kafkaConfig = KafkaConfig(
            brokers = kafkaContainer.bootstrapServers,
            certificatePath = "",
            privateKeyPath = "",
            caPath = "",
            credstorePassword = "",
            keystorePath = "",
            truststorePath = "",
            topic = topic,
        )
        val consumer = DataCollectorConsumer(kafkaConfig, gitHubRepository, dataCollectorRepository, TEST_POLL_TIMEOUT)
        val producer = KafkaProducer<String, String>(
            mapOf(
                ProducerConfig.BOOTSTRAP_SERVERS_CONFIG to kafkaContainer.bootstrapServers,
                ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG to StringSerializer::class.java.name,
                ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG to StringSerializer::class.java.name,
            )
        )
        try {
            consumer.start(this)
            awaitCondition(timeoutMs = 15000, message = "Consumer did not become ready") { consumer.isReady() }
            producer.send(ProducerRecord(topic, key, value)).get()
            awaitCondition(message = "Kafka message with key $key was not stored", condition = stored)
        } finally {
            producer.close()
            consumer.stop()
        }
    }

    private fun postCallback(path: String, body: String) = testApplication {
        application {
            testModule(
                tokenIntrospectionService = dataCollectorToken,
                gitHubRepository = gitHubRepository,
                dataCollectorRepository = dataCollectorRepository,
                sseEventLogRepository = sseEventLogRepository,
            )
        }

        val response = client.post(path) {
            header(HttpHeaders.Authorization, "Bearer data-collector")
            contentType(ContentType.Application.Json)
            setBody(body)
        }

        assertEquals(HttpStatusCode.NoContent, response.status)
    }

    @Test
    fun `should store vulnerability data identically via callback and Kafka`() {
        sendViaKafka(KafkaKey.GITHUB_VULNERABILITY_DATA, repositoryPayload("navikt/via-kafka")) {
            gitHubRepository.getVulnerabilities("navikt/via-kafka").size == 2
        }
        postCallback("/callbacks/github/vulnerabilities", repositoryPayload("navikt/via-callback"))

        runBlocking {
            val kafkaRepo = gitHubRepository.getRepository("navikt/via-kafka")!!
            val callbackRepo = gitHubRepository.getRepository("navikt/via-callback")!!
            assertEquals(kafkaRepo.naisTeams, callbackRepo.naisTeams)

            suspend fun normalize(name: String) =
                gitHubRepository.getVulnerabilities(name)
                    .map { it.copy(id = 0, nameWithOwner = "", createdAt = Instant.EPOCH, updatedAt = Instant.EPOCH) }
                    .sortedBy { it.severity }

            val callbackVulnerabilities = normalize("navikt/via-callback")
            assertEquals(2, callbackVulnerabilities.size)
            assertEquals(normalize("navikt/via-kafka"), callbackVulnerabilities)
        }
    }

    @Test
    fun `should store check results identically via callback and Kafka`() {
        sendViaKafka("CheckResult", checksPayload("navikt/checks-kafka", "team-kafka")) {
            dataCollectorRepository.allForOwner(listOf("team-kafka")).isNotEmpty()
        }
        postCallback("/callbacks/checks", checksPayload("navikt/checks-callback", "team-callback"))

        runBlocking {
            val viaKafka = dataCollectorRepository.allForOwner(listOf("team-kafka"))["navikt/checks-kafka"]!!
            val viaCallback = dataCollectorRepository.allForOwner(listOf("team-callback"))["navikt/checks-callback"]!!
            assertEquals(2, viaCallback.size)
            assertEquals(viaKafka.sortedBy { it.name }, viaCallback.sortedBy { it.name })
        }
    }

    @Test
    fun `should write sync signals to the SSE event log`() {
        val lastId = runBlocking { sseEventLogRepository.latestEventId() }

        postCallback("/callbacks/github/sync/started", """{"teams": ["team-a"], "timestamp": "2026-01-01T10:00:00Z"}""")
        postCallback("/callbacks/github/sync/complete", """{"teams": ["team-a"], "timestamp": "2026-01-01T10:05:00Z"}""")

        val events = runBlocking { sseEventLogRepository.eventsAfter(lastId).map { it.event } }
        assertEquals(
            listOf(
                SseEvent.GitHubVulnSyncStarted(listOf("team-a"), "2026-01-01T10:00:00Z"),
                SseEvent.GitHubVulnSyncComplete(listOf("team-a"), "2026-01-01T10:05:00Z"),
            ),
            events,
        )
    }
}
