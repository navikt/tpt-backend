package no.nav.tpt.infrastructure.kafka

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import kotlinx.coroutines.runBlocking
import no.nav.tpt.infrastructure.datacollector.DataCollectorRepositoryImpl
import no.nav.tpt.infrastructure.datacollector.DatacollectorRepository
import no.nav.tpt.infrastructure.github.GitHubRepository
import no.nav.tpt.infrastructure.github.GitHubRepositoryImpl
import no.nav.tpt.plugins.KAFKA_WAIT_STRATEGY
import org.apache.kafka.clients.producer.KafkaProducer
import org.apache.kafka.clients.producer.ProducerConfig
import org.apache.kafka.clients.producer.ProducerRecord
import org.apache.kafka.common.serialization.StringSerializer
import org.flywaydb.core.Flyway
import org.jetbrains.exposed.v1.jdbc.Database
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import org.testcontainers.kafka.KafkaContainer
import org.testcontainers.utility.DockerImageName
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@Testcontainers
class DataCollectorConsumerIntegrationTest {

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

        private lateinit var database: Database
        private lateinit var gitHubRepository: GitHubRepository
        private lateinit var dataCollectorRepository: DatacollectorRepository

        @JvmStatic
        @BeforeAll
        fun setUpClass() {
            val hikariConfig = HikariConfig().apply {
                jdbcUrl = postgresContainer.jdbcUrl
                username = postgresContainer.username
                password = postgresContainer.password
                driverClassName = "org.postgresql.Driver"
            }
            val dataSource = HikariDataSource(hikariConfig)

            Flyway.configure()
                .dataSource(dataSource)
                .locations("classpath:db/migration")
                .load()
                .migrate()

            database = Database.connect(dataSource)
            gitHubRepository = GitHubRepositoryImpl(database)
            dataCollectorRepository = DataCollectorRepositoryImpl(database)
        }
    }

    private val testTopic = "test-github-repo-topic"
    private lateinit var kafkaConsumer: DataCollectorConsumer
    private lateinit var kafkaProducer: KafkaProducer<String, String>

    @BeforeEach
    fun setup() {
        val kafkaConfig = KafkaConfig(
            brokers = kafkaContainer.bootstrapServers,
            certificatePath = "",
            privateKeyPath = "",
            caPath = "",
            credstorePassword = "",
            keystorePath = "",
            truststorePath = "",
            topic = testTopic,
        )
        kafkaConsumer = DataCollectorConsumer(kafkaConfig, gitHubRepository, dataCollectorRepository, TEST_POLL_TIMEOUT)

        kafkaProducer = KafkaProducer(
            mapOf(
                ProducerConfig.BOOTSTRAP_SERVERS_CONFIG to kafkaContainer.bootstrapServers,
                ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG to StringSerializer::class.java.name,
                ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG to StringSerializer::class.java.name,
                ProducerConfig.ACKS_CONFIG to "all",
            )
        )
    }

    @AfterEach
    fun teardown() {
        kafkaProducer.close()
    }

    @Test
    fun `should successfully consume and store valid GitHub repository message`() = runBlocking {
        val validMessage = """
            {
              "nameWithOwner": "navikt/test-app",
              "naisTeams": ["team-awesome", "team-security"],
              "vulnerabilities": [
                {
                  "severity": "CRITICAL",
                  "identifiers": [
                    {"value": "CVE-2024-1234", "type": "CVE"},
                    {"value": "GHSA-xxxx-yyyy-zzzz", "type": "GHSA"}
                  ]
                }
              ]
            }
        """.trimIndent()

        try {
            kafkaConsumer.start(this)
            awaitCondition(message = "Consumer did not become ready") { kafkaConsumer.isReady() }
            kafkaProducer.send(ProducerRecord(testTopic, KafkaKey.GITHUB_VULNERABILITY_DATA, validMessage)).get()

            awaitCondition(message = "Repository navikt/test-app was not stored") {
                gitHubRepository.getRepository("navikt/test-app") != null
            }

            val storedRepo = gitHubRepository.getRepository("navikt/test-app")!!
            assertEquals("navikt/test-app", storedRepo.nameWithOwner)
            assertEquals(2, storedRepo.naisTeams.size)
            assertEquals("team-awesome", storedRepo.naisTeams[0])
            assertEquals("team-security", storedRepo.naisTeams[1])

            awaitCondition(message = "Vulnerabilities for navikt/test-app were not stored") {
                gitHubRepository.getVulnerabilities("navikt/test-app").size == 1
            }

            val vulnerabilities = gitHubRepository.getVulnerabilities("navikt/test-app")
            assertEquals("CRITICAL", vulnerabilities[0].severity)
            assertEquals(2, vulnerabilities[0].identifiers.size)
            assertEquals("CVE-2024-1234", vulnerabilities[0].identifiers[0].value)
            assertEquals("CVE", vulnerabilities[0].identifiers[0].type)
            assertEquals("GHSA-xxxx-yyyy-zzzz", vulnerabilities[0].identifiers[1].value)
            assertEquals("GHSA", vulnerabilities[0].identifiers[1].type)
        } finally {
            kafkaConsumer.stop()
        }
    }

    @Test
    fun `should handle multiple vulnerabilities with multiple identifiers`() = runBlocking {
        val messageWithMultipleVulns = """
            {
              "nameWithOwner": "navikt/multi-vuln-app",
              "naisTeams": ["team-a"],
              "vulnerabilities": [
                {
                  "severity": "CRITICAL",
                  "identifiers": [
                    {"value": "CVE-2024-1111", "type": "CVE"},
                    {"value": "GHSA-aaaa-bbbb-cccc", "type": "GHSA"}
                  ]
                },
                {
                  "severity": "HIGH",
                  "identifiers": [
                    {"value": "CVE-2024-2222", "type": "CVE"}
                  ]
                },
                {
                  "severity": "MEDIUM",
                  "identifiers": [
                    {"value": "CVE-2024-3333", "type": "CVE"},
                    {"value": "GHSA-dddd-eeee-ffff", "type": "GHSA"},
                    {"value": "SNYK-1234567", "type": "SNYK"}
                  ]
                }
              ]
            }
        """.trimIndent()

        try {
            kafkaConsumer.start(this)
            awaitCondition(message = "Consumer did not become ready") { kafkaConsumer.isReady() }
            kafkaProducer.send(ProducerRecord(testTopic, KafkaKey.GITHUB_VULNERABILITY_DATA, messageWithMultipleVulns)).get()

            awaitCondition(message = "3 vulnerabilities for navikt/multi-vuln-app were not stored") {
                gitHubRepository.getVulnerabilities("navikt/multi-vuln-app").size == 3
            }

            val vulnerabilities = gitHubRepository.getVulnerabilities("navikt/multi-vuln-app")
            assertEquals("CRITICAL", vulnerabilities[0].severity)
            assertEquals(2, vulnerabilities[0].identifiers.size)
            assertEquals("HIGH", vulnerabilities[1].severity)
            assertEquals(1, vulnerabilities[1].identifiers.size)
            assertEquals("MEDIUM", vulnerabilities[2].severity)
            assertEquals(3, vulnerabilities[2].identifiers.size)
            assertEquals("SNYK-1234567", vulnerabilities[2].identifiers[2].value)
            assertEquals("SNYK", vulnerabilities[2].identifiers[2].type)
        } finally {
            kafkaConsumer.stop()
        }
    }

    @Test
    fun `should update existing repository and replace vulnerabilities`() = runBlocking {
        val initialMessage = """
            {
              "nameWithOwner": "navikt/update-test",
              "naisTeams": ["team-old"],
              "vulnerabilities": [
                {
                  "severity": "LOW",
                  "identifiers": [{"value": "CVE-2024-9999", "type": "CVE"}]
                }
              ]
            }
        """.trimIndent()

        val updatedMessage = """
            {
              "nameWithOwner": "navikt/update-test",
              "naisTeams": ["team-new", "team-another"],
              "vulnerabilities": [
                {
                  "severity": "CRITICAL",
                  "identifiers": [{"value": "CVE-2024-0001", "type": "CVE"}]
                }
              ]
            }
        """.trimIndent()

        try {
            kafkaConsumer.start(this)
            awaitCondition(message = "Consumer did not become ready") { kafkaConsumer.isReady() }
            kafkaProducer.send(ProducerRecord(testTopic, KafkaKey.GITHUB_VULNERABILITY_DATA, initialMessage)).get()

            awaitCondition(message = "Initial state for navikt/update-test was not stored") {
                gitHubRepository.getRepository("navikt/update-test")?.naisTeams?.contains("team-old") == true
            }

            kafkaProducer.send(ProducerRecord(testTopic, KafkaKey.GITHUB_VULNERABILITY_DATA, updatedMessage)).get()

            awaitCondition(message = "Updated state for navikt/update-test was not stored") {
                gitHubRepository.getRepository("navikt/update-test")?.naisTeams?.contains("team-new") == true
            }

            val updatedRepo = gitHubRepository.getRepository("navikt/update-test")!!
            assertEquals(2, updatedRepo.naisTeams.size)
            assertEquals("team-new", updatedRepo.naisTeams[0])
            assertEquals("team-another", updatedRepo.naisTeams[1])

            awaitCondition(message = "Updated vulnerability for navikt/update-test was not stored") {
                gitHubRepository.getVulnerabilities("navikt/update-test").firstOrNull()?.severity == "CRITICAL"
            }

            val updatedVulns = gitHubRepository.getVulnerabilities("navikt/update-test")
            assertEquals(1, updatedVulns.size)
            assertEquals("CVE-2024-0001", updatedVulns[0].identifiers[0].value)
        } finally {
            kafkaConsumer.stop()
        }
    }

    @Test
    fun `should handle repository with no vulnerabilities`() = runBlocking {
        val messageWithNoVulns = """
            {
              "nameWithOwner": "navikt/no-vulns",
              "naisTeams": ["team-safe"],
              "vulnerabilities": []
            }
        """.trimIndent()

        try {
            kafkaConsumer.start(this)
            awaitCondition(message = "Consumer did not become ready") { kafkaConsumer.isReady() }
            kafkaProducer.send(ProducerRecord(testTopic, KafkaKey.GITHUB_VULNERABILITY_DATA, messageWithNoVulns)).get()

            awaitCondition(message = "Repository navikt/no-vulns was not stored") {
                gitHubRepository.getRepository("navikt/no-vulns") != null
            }

            val repo = gitHubRepository.getRepository("navikt/no-vulns")!!
            assertEquals("team-safe", repo.naisTeams[0])
            assertEquals(0, gitHubRepository.getVulnerabilities("navikt/no-vulns").size)
        } finally {
            kafkaConsumer.stop()
        }
    }

    @Test
    fun `should gracefully handle malformed JSON message`() = runBlocking {
        // Missing comma between fields — kotlinx.serialization parses this leniently and stores
        // the repo. The important thing is the consumer stays healthy and does not crash.
        val malformedMessage = """
            {
              "nameWithOwner": "navikt/bad-json",
              "naisTeams": ["team-test"]
              "vulnerabilities": []
            }
        """.trimIndent()

        try {
            kafkaConsumer.start(this)
            awaitCondition(message = "Consumer did not become ready") { kafkaConsumer.isReady() }
            kafkaProducer.send(ProducerRecord(testTopic, KafkaKey.GITHUB_VULNERABILITY_DATA, malformedMessage)).get()

            awaitCondition(message = "Consumer did not stay healthy after malformed message") { kafkaConsumer.isReady() }
            assertTrue(kafkaConsumer.isHealthy(), "Consumer should remain healthy after a bad message")
        } finally {
            kafkaConsumer.stop()
        }
    }

    @Test
    fun `should handle missing required fields`() = runBlocking {
        // naisTeams is absent — coerced to null and stored as empty list. The repo is stored.
        val missingFieldsMessage = """
            {
              "nameWithOwner": "navikt/missing-fields",
              "vulnerabilities": []
            }
        """.trimIndent()

        try {
            kafkaConsumer.start(this)
            awaitCondition(message = "Consumer did not become ready") { kafkaConsumer.isReady() }
            kafkaProducer.send(ProducerRecord(testTopic, KafkaKey.GITHUB_VULNERABILITY_DATA, missingFieldsMessage)).get()

            awaitCondition(message = "Repository navikt/missing-fields was not stored") {
                gitHubRepository.getRepository("navikt/missing-fields") != null
            }

            val repo = gitHubRepository.getRepository("navikt/missing-fields")!!
            assertEquals(emptyList(), repo.naisTeams)
        } finally {
            kafkaConsumer.stop()
        }
    }

    @Test
    fun `should handle invalid data types`() = runBlocking {
        // naisTeams as a string instead of array — coerceInputValues handles this gracefully
        val invalidTypesMessage = """
            {
              "nameWithOwner": "navikt/invalid-types",
              "naisTeams": "not-an-array",
              "vulnerabilities": []
            }
        """.trimIndent()

        try {
            kafkaConsumer.start(this)
            awaitCondition(message = "Consumer did not become ready") { kafkaConsumer.isReady() }
            kafkaProducer.send(ProducerRecord(testTopic, KafkaKey.GITHUB_VULNERABILITY_DATA, invalidTypesMessage)).get()

            awaitCondition(message = "Consumer did not stay healthy after invalid type message") { kafkaConsumer.isReady() }
            assertTrue(kafkaConsumer.isHealthy(), "Consumer should remain healthy after invalid type message")
        } finally {
            kafkaConsumer.stop()
        }
    }

    @Test
    fun `should process multiple messages in sequence`() = runBlocking {
        try {
            kafkaConsumer.start(this)
            awaitCondition(message = "Consumer did not become ready") { kafkaConsumer.isReady() }

            val repos = listOf("app-1", "app-2", "app-3")
            repos.forEach { repoName ->
                val message = """
                {
                  "nameWithOwner": "navikt/$repoName",
                  "naisTeams": ["team-$repoName"],
                  "vulnerabilities": [
                    {
                      "severity": "HIGH",
                      "identifiers": [{"value": "CVE-2024-$repoName", "type": "CVE"}]
                    }
                  ]
                }
            """.trimIndent()
                kafkaProducer.send(ProducerRecord(testTopic, KafkaKey.GITHUB_VULNERABILITY_DATA, message)).get()
            }

            repos.forEach { repoName ->
                awaitCondition(message = "Repository navikt/$repoName was not stored") {
                    gitHubRepository.getRepository("navikt/$repoName") != null
                }
                val repo = gitHubRepository.getRepository("navikt/$repoName")!!
                assertEquals("team-$repoName", repo.naisTeams[0])

                awaitCondition(message = "Vulnerability for navikt/$repoName was not stored") {
                    gitHubRepository.getVulnerabilities("navikt/$repoName").isNotEmpty()
                }
                val vulns = gitHubRepository.getVulnerabilities("navikt/$repoName")
                assertEquals(1, vulns.size)
                assertEquals("HIGH", vulns[0].severity)
            }
        } finally {
            kafkaConsumer.stop()
        }
    }

    @Test
    fun `should handle empty repository name`() = runBlocking {
        // Empty nameWithOwner is stored as-is — no validation guard in the repository layer.
        val emptyRepoNameMessage = """
            {
              "nameWithOwner": "",
              "naisTeams": ["team-test"],
              "vulnerabilities": []
            }
        """.trimIndent()

        try {
            kafkaConsumer.start(this)
            awaitCondition(message = "Consumer did not become ready") { kafkaConsumer.isReady() }
            kafkaProducer.send(ProducerRecord(testTopic, KafkaKey.GITHUB_VULNERABILITY_DATA, emptyRepoNameMessage)).get()

            awaitCondition(message = "Repository with empty name was not stored") {
                gitHubRepository.getRepository("") != null
            }

            val repo = gitHubRepository.getRepository("")!!
            assertEquals("", repo.nameWithOwner)
            assertEquals(listOf("team-test"), repo.naisTeams)
        } finally {
            kafkaConsumer.stop()
        }
    }

    @Test
    fun `should consume and store extended vulnerability fields from Kafka message`() = runBlocking {
        val comprehensiveMessage = """
            {
              "nameWithOwner": "navikt/comprehensive-test-repo",
              "naisTeams": ["security-team"],
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
                  "severity": "MODERATE",
                  "identifiers": [
                    {"value": "CVE-2024-1111", "type": "CVE"}
                  ],
                  "dependencyScope": "DEVELOPMENT",
                  "publishedAt": "2024-02-20T14:00:00Z",
                  "cvssScore": 5.3,
                  "summary": "Moderate severity issue",
                  "packageEcosystem": "MAVEN",
                  "packageName": "com.example:test-lib"
                }
              ]
            }
        """.trimIndent()

        try {
            kafkaConsumer.start(this)
            awaitCondition(message = "Consumer did not become ready") { kafkaConsumer.isReady() }
            kafkaProducer.send(ProducerRecord(testTopic, KafkaKey.GITHUB_VULNERABILITY_DATA, comprehensiveMessage)).get()

            awaitCondition(message = "2 vulnerabilities for navikt/comprehensive-test-repo were not stored") {
                gitHubRepository.getVulnerabilities("navikt/comprehensive-test-repo").size == 2
            }

            val vulnerabilities = gitHubRepository.getVulnerabilities("navikt/comprehensive-test-repo")
            val critical = vulnerabilities.find { it.severity == "CRITICAL" }!!
            assertEquals("RUNTIME", critical.dependencyScope)
            assertEquals("https://github.com/org/repo/pull/42", critical.dependabotUpdatePullRequestUrl)
            assertEquals(9.8, critical.cvssScore)
            assertEquals("Critical vulnerability in dependency", critical.summary)
            assertEquals("NPM", critical.packageEcosystem)
            assertEquals("vulnerable-package", critical.packageName)
            assertNotNull(critical.publishedAt)

            val moderate = vulnerabilities.find { it.severity == "MODERATE" }!!
            assertEquals("DEVELOPMENT", moderate.dependencyScope)
            assertNull(moderate.dependabotUpdatePullRequestUrl)
            assertEquals(5.3, moderate.cvssScore)
            assertEquals("Moderate severity issue", moderate.summary)
            assertEquals("MAVEN", moderate.packageEcosystem)
            assertEquals("com.example:test-lib", moderate.packageName)
            assertNotNull(moderate.publishedAt)
        } finally {
            kafkaConsumer.stop()
        }
    }

    @Test
    fun `should consume and store dockerfile features message`() = runBlocking {
        // The dockerfile_features message updates an existing repo's usesDistroless flag.
        // We first create the repo, then send the dockerfile_features update.
        val repoMessage = """
            {
              "nameWithOwner": "navikt/test",
              "naisTeams": ["team-test"],
              "vulnerabilities": []
            }
        """.trimIndent()
        val dockerfileFeaturesMessage = """
            {
              "repoName": "navikt/test",
              "usesDistroless": true
            }
        """.trimIndent()

        try {
            kafkaConsumer.start(this)
            awaitCondition(message = "Consumer did not become ready") { kafkaConsumer.isReady() }
            kafkaProducer.send(ProducerRecord(testTopic, KafkaKey.GITHUB_VULNERABILITY_DATA, repoMessage)).get()

            awaitCondition(message = "navikt/test was not initially stored") {
                gitHubRepository.getRepository("navikt/test") != null
            }

            kafkaProducer.send(ProducerRecord(testTopic, "dockerfile_features", dockerfileFeaturesMessage)).get()

            awaitCondition(message = "navikt/test was not updated with usesDistroless=true") {
                gitHubRepository.getRepository("navikt/test")?.usesDistroless == true
            }

            val storedRepo = gitHubRepository.getRepository("navikt/test")!!
            assertEquals("navikt/test", storedRepo.nameWithOwner)
            assertEquals(true, storedRepo.usesDistroless)
        } finally {
            kafkaConsumer.stop()
        }
    }

    @Test
    fun `should update existing repository with dockerfile features`() = runBlocking {
        val initialRepoMessage = """
            {
              "nameWithOwner": "navikt/existing-repo",
              "naisTeams": ["team-test"],
              "vulnerabilities": []
            }
        """.trimIndent()

        val dockerfileFeaturesMessage = """
            {
              "repoName": "navikt/existing-repo",
              "usesDistroless": false
            }
        """.trimIndent()

        try {
            kafkaConsumer.start(this)
            awaitCondition(message = "Consumer did not become ready") { kafkaConsumer.isReady() }
            kafkaProducer.send(ProducerRecord(testTopic, KafkaKey.GITHUB_VULNERABILITY_DATA, initialRepoMessage)).get()

            awaitCondition(message = "navikt/existing-repo was not initially stored") {
                gitHubRepository.getRepository("navikt/existing-repo") != null
            }
            assertNull(gitHubRepository.getRepository("navikt/existing-repo")!!.usesDistroless)

            kafkaProducer.send(ProducerRecord(testTopic, "dockerfile_features", dockerfileFeaturesMessage)).get()

            awaitCondition(message = "navikt/existing-repo was not updated with usesDistroless=false") {
                gitHubRepository.getRepository("navikt/existing-repo")?.usesDistroless != null
            }

            val updatedRepo = gitHubRepository.getRepository("navikt/existing-repo")!!
            assertEquals(false, updatedRepo.usesDistroless)
            assertEquals("team-test", updatedRepo.naisTeams[0])
        } finally {
            kafkaConsumer.stop()
        }
    }
}
