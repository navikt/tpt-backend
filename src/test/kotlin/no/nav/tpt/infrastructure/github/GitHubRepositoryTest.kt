package no.nav.tpt.infrastructure.github

import kotlinx.coroutines.runBlocking
import no.nav.tpt.infrastructure.config.AppConfig
import no.nav.tpt.infrastructure.database.DatabaseFactory
import no.nav.tpt.infrastructure.kafka.GitHubIdentifierMessage
import no.nav.tpt.infrastructure.kafka.GitHubRepositoryMessage
import no.nav.tpt.infrastructure.kafka.GitHubVulnerabilityMessage
import org.junit.Before
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class GitHubRepositoryTest {

    private lateinit var repository: GitHubRepository
    private lateinit var database: org.jetbrains.exposed.sql.Database

    @Before
    fun setup() {
        val testConfig = AppConfig.fromEnvironment()
        database = DatabaseFactory.init(testConfig)
        repository = GitHubRepositoryImpl(database)
    }

    @Test
    fun `should insert new repository with teams and vulnerabilities`() = runBlocking {
        val message = GitHubRepositoryMessage(
            nameWithOwner = "navikt/test-repo-${System.currentTimeMillis()}",
            naisTeams = listOf("team-a", "team-b", "team-c"),
            vulnerabilities = listOf(
                GitHubVulnerabilityMessage(
                    severity = "CRITICAL",
                    identifiers = listOf(
                        GitHubIdentifierMessage("CVE-2024-1234", "CVE"),
                        GitHubIdentifierMessage("GHSA-xxxx-yyyy-zzzz", "GHSA")
                    )
                )
            )
        )

        repository.upsertRepositoryData(message)

        val result = repository.getRepository(message.nameWithOwner)
        assertNotNull(result)
        assertEquals(message.nameWithOwner, result.nameWithOwner)
        assertEquals(3, result.naisTeams.size)
        assertTrue(result.naisTeams.containsAll(listOf("team-a", "team-b", "team-c")))

        val vulnerabilities = repository.getVulnerabilities(message.nameWithOwner)
        assertEquals(1, vulnerabilities.size)
        assertEquals("CRITICAL", vulnerabilities[0].severity)
        assertEquals(2, vulnerabilities[0].identifiers.size)
    }

    @Test
    fun `should update existing repository and replace vulnerabilities`() = runBlocking {
        val nameWithOwner = "navikt/test-repo-update-${System.currentTimeMillis()}"

        val initialMessage = GitHubRepositoryMessage(
            nameWithOwner = nameWithOwner,
            naisTeams = listOf("team-a", "team-b"),
            vulnerabilities = listOf(
                GitHubVulnerabilityMessage(
                    severity = "HIGH",
                    identifiers = listOf(GitHubIdentifierMessage("CVE-2024-1111", "CVE"))
                )
            )
        )

        repository.upsertRepositoryData(initialMessage)
        val initial = repository.getRepository(nameWithOwner)
        assertNotNull(initial)
        assertEquals(2, initial.naisTeams.size)

        val initialVulns = repository.getVulnerabilities(nameWithOwner)
        assertEquals(1, initialVulns.size)

        val updatedMessage = GitHubRepositoryMessage(
            nameWithOwner = nameWithOwner,
            naisTeams = listOf("team-a", "team-b", "team-c", "team-d"),
            vulnerabilities = listOf(
                GitHubVulnerabilityMessage(
                    severity = "CRITICAL",
                    identifiers = listOf(
                        GitHubIdentifierMessage("CVE-2024-2222", "CVE"),
                        GitHubIdentifierMessage("GHSA-aaaa-bbbb-cccc", "GHSA")
                    )
                ),
                GitHubVulnerabilityMessage(
                    severity = "MEDIUM",
                    identifiers = listOf(GitHubIdentifierMessage("CVE-2024-3333", "CVE"))
                )
            )
        )

        repository.upsertRepositoryData(updatedMessage)
        val updated = repository.getRepository(nameWithOwner)
        assertNotNull(updated)
        assertEquals(4, updated.naisTeams.size)
        assertTrue(updated.updatedAt.isAfter(initial.updatedAt) || updated.updatedAt == initial.updatedAt)

        val updatedVulns = repository.getVulnerabilities(nameWithOwner)
        assertEquals(2, updatedVulns.size)
        assertEquals("CRITICAL", updatedVulns[0].severity)
        assertEquals("MEDIUM", updatedVulns[1].severity)
    }

    @Test
    fun `should return null for non-existent repository`() = runBlocking {
        val result = repository.getRepository("non-existent-repo-${System.currentTimeMillis()}")
        assertNull(result)
    }

    @Test
    fun `should return empty list for repository with no vulnerabilities`() = runBlocking {
        val message = GitHubRepositoryMessage(
            nameWithOwner = "navikt/no-vulns-${System.currentTimeMillis()}",
            naisTeams = listOf("team-a"),
            vulnerabilities = emptyList()
        )

        repository.upsertRepositoryData(message)
        val vulnerabilities = repository.getVulnerabilities(message.nameWithOwner)
        assertEquals(0, vulnerabilities.size)
    }

    @Test
    fun `should store and retrieve extended vulnerability fields`() = runBlocking {
        val nameWithOwner = "navikt/comprehensive-test-repo-${System.currentTimeMillis()}"
        val message = GitHubRepositoryMessage(
            nameWithOwner = nameWithOwner,
            naisTeams = listOf("security-team"),
            vulnerabilities = listOf(
                GitHubVulnerabilityMessage(
                    severity = "CRITICAL",
                    identifiers = listOf(
                        GitHubIdentifierMessage("CVE-2024-9999", "CVE"),
                        GitHubIdentifierMessage("GHSA-abcd-efgh-ijkl", "GHSA")
                    ),
                    dependencyScope = "RUNTIME",
                    dependabotUpdatePullRequestUrl = "https://github.com/org/repo/pull/42",
                    publishedAt = "2024-01-15T10:30:00Z",
                    cvssScore = 9.8,
                    summary = "Critical vulnerability in dependency",
                    packageEcosystem = "NPM",
                    packageName = "vulnerable-package"
                ),
                GitHubVulnerabilityMessage(
                    severity = "MODERATE",
                    identifiers = listOf(
                        GitHubIdentifierMessage("CVE-2024-1111", "CVE")
                    ),
                    dependencyScope = "DEVELOPMENT",
                    publishedAt = "2024-02-20T14:00:00Z",
                    cvssScore = 5.3,
                    summary = "Moderate severity issue",
                    packageEcosystem = "MAVEN",
                    packageName = "com.example:test-lib"
                )
            )
        )

        repository.upsertRepositoryData(message)

        val vulnerabilities = repository.getVulnerabilities(nameWithOwner)
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
    }
}

