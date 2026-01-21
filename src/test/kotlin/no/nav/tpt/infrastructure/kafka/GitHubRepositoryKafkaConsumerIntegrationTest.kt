package no.nav.tpt.infrastructure.kafka

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import no.nav.tpt.infrastructure.github.GitHubRepository
import no.nav.tpt.infrastructure.github.GitHubRepositoryImpl
import no.nav.tpt.plugins.KAFKA_WAIT_STRATEGY
import org.apache.kafka.clients.producer.KafkaProducer
import org.apache.kafka.clients.producer.ProducerConfig
import org.apache.kafka.clients.producer.ProducerRecord
import org.apache.kafka.common.serialization.StringSerializer
import org.flywaydb.core.Flyway
import org.jetbrains.exposed.sql.Database
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.containers.wait.strategy.Wait
import org.testcontainers.kafka.KafkaContainer
import org.testcontainers.utility.DockerImageName
import java.time.Duration as JavaDuration
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class GitHubRepositoryKafkaConsumerIntegrationTest {

    private lateinit var postgresContainer: PostgreSQLContainer<*>
    private lateinit var kafkaContainer: KafkaContainer
    private lateinit var database: Database
    private lateinit var repository: GitHubRepository
    private lateinit var kafkaConsumer: GitHubRepositoryKafkaConsumer
    private lateinit var kafkaProducer: KafkaProducer<String, String>

    private val testTopic = "test-github-repo-topic"

    @Before
    fun setup() {
        postgresContainer = PostgreSQLContainer(DockerImageName.parse("postgres:17"))
            .withDatabaseName("test_db")
            .withUsername("test")
            .withPassword("test")
        postgresContainer.start()

        kafkaContainer = KafkaContainer(DockerImageName.parse("apache/kafka:3.9.0"))
            .withExposedPorts(9092, 9093)
            .withEnv("KAFKA_NODE_ID", "1")
            .withEnv("KAFKA_PROCESS_ROLES", "broker,controller")
            .withEnv("KAFKA_LISTENERS", "PLAINTEXT://0.0.0.0:9092,CONTROLLER://0.0.0.0:9093")
            .withEnv("KAFKA_ADVERTISED_LISTENERS", "PLAINTEXT://localhost:9092")
            .withEnv("KAFKA_CONTROLLER_LISTENER_NAMES", "CONTROLLER")
            .withEnv("KAFKA_LISTENER_SECURITY_PROTOCOL_MAP", "CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT")
            .withEnv("KAFKA_CONTROLLER_QUORUM_VOTERS", "1@localhost:9093")
            .withEnv("KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR", "1")
            .withEnv("KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR", "1")
            .withEnv("KAFKA_TRANSACTION_STATE_LOG_MIN_ISR", "1")
            .withEnv("KAFKA_LOG_DIRS", "/tmp/kraft-combined-logs")
            .withEnv("CLUSTER_ID", "MkU3OEVBNTcwNTJENDM2Qk")
            .waitingFor(KAFKA_WAIT_STRATEGY)
        kafkaContainer.start()

        val hikariConfig = HikariConfig().apply {
            jdbcUrl = postgresContainer.jdbcUrl
            username = postgresContainer.username
            password = postgresContainer.password
            driverClassName = "org.postgresql.Driver"
        }
        val dataSource = HikariDataSource(hikariConfig)

        val flyway = Flyway.configure()
            .dataSource(dataSource)
            .locations("classpath:db/migration")
            .load()
        flyway.migrate()

        database = Database.connect(dataSource)
        repository = GitHubRepositoryImpl(database)

        val kafkaPort = kafkaContainer.getMappedPort(9092)
        val kafkaConfig = KafkaConfig(
            brokers = "localhost:$kafkaPort",
            certificatePath = "",
            privateKeyPath = "",
            caPath = "",
            credstorePassword = "",
            keystorePath = "",
            truststorePath = "",
            topic = testTopic
        )

        kafkaConsumer = GitHubRepositoryKafkaConsumer(kafkaConfig, repository)

        val producerProps = mapOf(
            ProducerConfig.BOOTSTRAP_SERVERS_CONFIG to "localhost:$kafkaPort",
            ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG to StringSerializer::class.java.name,
            ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG to StringSerializer::class.java.name,
            ProducerConfig.ACKS_CONFIG to "all"
        )
        kafkaProducer = KafkaProducer(producerProps)
    }

    @After
    fun teardown() {
        kafkaProducer.close()
        postgresContainer.stop()
        kafkaContainer.stop()
    }

    @Test
    fun `should successfully consume and store valid GitHub repository message`() = runBlocking {
        val validMessage = """
            {
              "repositoryName": "navikt/test-app",
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
            delay(2000)

            val record = ProducerRecord(testTopic, "test-key", validMessage)
            kafkaProducer.send(record).get()

            delay(3000)

            val storedRepo = repository.getRepository("navikt/test-app")
            assertNotNull(storedRepo)
            assertEquals("navikt/test-app", storedRepo.repositoryName)
            assertEquals(2, storedRepo.naisTeams.size)
            assertEquals("team-awesome", storedRepo.naisTeams[0])
            assertEquals("team-security", storedRepo.naisTeams[1])

            val vulnerabilities = repository.getVulnerabilities("navikt/test-app")
            assertEquals(1, vulnerabilities.size)
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
              "repositoryName": "navikt/multi-vuln-app",
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
            delay(2000)

            kafkaProducer.send(ProducerRecord(testTopic, "multi-key", messageWithMultipleVulns)).get()
            delay(3000)

            val vulnerabilities = repository.getVulnerabilities("navikt/multi-vuln-app")
            assertEquals(3, vulnerabilities.size)

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
              "repositoryName": "navikt/update-test",
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
              "repositoryName": "navikt/update-test",
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
            delay(2000)

            kafkaProducer.send(ProducerRecord(testTopic, "update-key", initialMessage)).get()
            delay(3000)

            val initialRepo = repository.getRepository("navikt/update-test")
            assertNotNull(initialRepo)
            assertEquals(1, initialRepo.naisTeams.size)
            assertEquals("team-old", initialRepo.naisTeams[0])

            val initialVulns = repository.getVulnerabilities("navikt/update-test")
            assertEquals(1, initialVulns.size)
            assertEquals("LOW", initialVulns[0].severity)

            kafkaProducer.send(ProducerRecord(testTopic, "update-key", updatedMessage)).get()
            delay(3000)

            val updatedRepo = repository.getRepository("navikt/update-test")
            assertNotNull(updatedRepo)
            assertEquals(2, updatedRepo.naisTeams.size)
            assertEquals("team-new", updatedRepo.naisTeams[0])
            assertEquals("team-another", updatedRepo.naisTeams[1])

            val updatedVulns = repository.getVulnerabilities("navikt/update-test")
            assertEquals(1, updatedVulns.size)
            assertEquals("CRITICAL", updatedVulns[0].severity)
            assertEquals("CVE-2024-0001", updatedVulns[0].identifiers[0].value)
        } finally {
            kafkaConsumer.stop()
        }
    }

    @Test
    fun `should handle repository with no vulnerabilities`() = runBlocking {
        val messageWithNoVulns = """
            {
              "repositoryName": "navikt/no-vulns",
              "naisTeams": ["team-safe"],
              "vulnerabilities": []
            }
        """.trimIndent()

        try {
            kafkaConsumer.start(this)
            delay(2000)

            kafkaProducer.send(ProducerRecord(testTopic, "no-vulns-key", messageWithNoVulns)).get()
            delay(3000)

            val repo = repository.getRepository("navikt/no-vulns")
            assertNotNull(repo)
            assertEquals("team-safe", repo.naisTeams[0])

            val vulnerabilities = repository.getVulnerabilities("navikt/no-vulns")
            assertEquals(0, vulnerabilities.size)
        } finally {
            kafkaConsumer.stop()
        }
    }

    @Test
    fun `should gracefully handle malformed JSON message`() = runBlocking {
        val malformedMessage = """
            {
              "repositoryName": "navikt/bad-json",
              "naisTeams": ["team-test"]
              "vulnerabilities": []
            }
        """.trimIndent()

        try {
            kafkaConsumer.start(this)
            delay(2000)

            kafkaProducer.send(ProducerRecord(testTopic, "bad-json-key", malformedMessage)).get()
            delay(3000)

            val repo = repository.getRepository("navikt/bad-json")
            assertNull(repo)
        } finally {
            kafkaConsumer.stop()
        }
    }

    @Test
    fun `should handle missing required fields`() = runBlocking {
        val missingFieldsMessage = """
            {
              "repositoryName": "navikt/missing-fields",
              "vulnerabilities": []
            }
        """.trimIndent()

        try {
            kafkaConsumer.start(this)
            delay(2000)

            kafkaProducer.send(ProducerRecord(testTopic, "missing-key", missingFieldsMessage)).get()
            delay(3000)

            val repo = repository.getRepository("navikt/missing-fields")
            assertNull(repo)
        } finally {
            kafkaConsumer.stop()
        }
    }

    @Test
    fun `should handle invalid data types`() = runBlocking {
        val invalidTypesMessage = """
            {
              "repositoryName": "navikt/invalid-types",
              "naisTeams": "not-an-array",
              "vulnerabilities": []
            }
        """.trimIndent()

        try {
            kafkaConsumer.start(this)
            delay(2000)

            kafkaProducer.send(ProducerRecord(testTopic, "invalid-type-key", invalidTypesMessage)).get()
            delay(3000)

            val repo = repository.getRepository("navikt/invalid-types")
            assertNull(repo)
        } finally {
            kafkaConsumer.stop()
        }
    }

    @Test
    fun `should process multiple messages in sequence`() = runBlocking {
        try {
            kafkaConsumer.start(this)
            delay(2000)

            val repos = listOf("app-1", "app-2", "app-3")
            repos.forEach { repoName ->
                val message = """
                {
                  "repositoryName": "navikt/$repoName",
                  "naisTeams": ["team-$repoName"],
                  "vulnerabilities": [
                    {
                      "severity": "HIGH",
                      "identifiers": [{"value": "CVE-2024-$repoName", "type": "CVE"}]
                    }
                  ]
                }
            """.trimIndent()
                kafkaProducer.send(ProducerRecord(testTopic, repoName, message)).get()
            }

            delay(5000)

            repos.forEach { repoName ->
                val repo = repository.getRepository("navikt/$repoName")
                assertNotNull(repo, "Repository navikt/$repoName should exist")
                assertEquals("team-$repoName", repo.naisTeams[0])

                val vulns = repository.getVulnerabilities("navikt/$repoName")
                assertEquals(1, vulns.size)
                assertEquals("HIGH", vulns[0].severity)
            }
        } finally {
            kafkaConsumer.stop()
        }
    }

    @Test
    fun `should handle empty repository name`() = runBlocking {
        val emptyRepoNameMessage = """
            {
              "repositoryName": "",
              "naisTeams": ["team-test"],
              "vulnerabilities": []
            }
        """.trimIndent()

        try {
            kafkaConsumer.start(this)
            delay(2000)

            kafkaProducer.send(ProducerRecord(testTopic, "empty-name-key", emptyRepoNameMessage)).get()
            delay(3000)

            val repo = repository.getRepository("")
            assertNull(repo)
        } finally {
            kafkaConsumer.stop()
        }
    }

    @Test
    fun `should consume and store extended vulnerability fields from Kafka message`() = runBlocking {
        val comprehensiveMessage = """
            {
              "repositoryName": "navikt/comprehensive-test-repo",
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
            delay(2000)

            kafkaProducer.send(ProducerRecord(testTopic, "comprehensive-key", comprehensiveMessage)).get()
            delay(3000)

            val storedRepo = repository.getRepository("navikt/comprehensive-test-repo")
            assertNotNull(storedRepo)
            assertEquals("navikt/comprehensive-test-repo", storedRepo.repositoryName)

            val vulnerabilities = repository.getVulnerabilities("navikt/comprehensive-test-repo")
            assertEquals(2, vulnerabilities.size)

            val critical = vulnerabilities.find { it.severity == "CRITICAL" }
            assertNotNull(critical)
            assertEquals("RUNTIME", critical.dependencyScope)
            assertEquals("https://github.com/org/repo/pull/42", critical.dependabotUpdatePullRequestUrl)
            assertEquals(9.8, critical.cvssScore)
            assertEquals("Critical vulnerability in dependency", critical.summary)
            assertEquals("NPM", critical.packageEcosystem)
            assertEquals("vulnerable-package", critical.packageName)
            assertNotNull(critical.publishedAt)

            val moderate = vulnerabilities.find { it.severity == "MODERATE" }
            assertNotNull(moderate)
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
}

