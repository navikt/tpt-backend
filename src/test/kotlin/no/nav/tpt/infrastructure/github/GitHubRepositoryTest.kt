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
            repositoryName = "navikt/test-repo-${System.currentTimeMillis()}",
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

        val result = repository.getRepository(message.repositoryName)
        assertNotNull(result)
        assertEquals(message.repositoryName, result.repositoryName)
        assertEquals(3, result.naisTeams.size)
        assertTrue(result.naisTeams.containsAll(listOf("team-a", "team-b", "team-c")))

        val vulnerabilities = repository.getVulnerabilities(message.repositoryName)
        assertEquals(1, vulnerabilities.size)
        assertEquals("CRITICAL", vulnerabilities[0].severity)
        assertEquals(2, vulnerabilities[0].identifiers.size)
    }

    @Test
    fun `should update existing repository and replace vulnerabilities`() = runBlocking {
        val repositoryName = "navikt/test-repo-update-${System.currentTimeMillis()}"

        val initialMessage = GitHubRepositoryMessage(
            repositoryName = repositoryName,
            naisTeams = listOf("team-a", "team-b"),
            vulnerabilities = listOf(
                GitHubVulnerabilityMessage(
                    severity = "HIGH",
                    identifiers = listOf(GitHubIdentifierMessage("CVE-2024-1111", "CVE"))
                )
            )
        )

        repository.upsertRepositoryData(initialMessage)
        val initial = repository.getRepository(repositoryName)
        assertNotNull(initial)
        assertEquals(2, initial.naisTeams.size)

        val initialVulns = repository.getVulnerabilities(repositoryName)
        assertEquals(1, initialVulns.size)

        val updatedMessage = GitHubRepositoryMessage(
            repositoryName = repositoryName,
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
        val updated = repository.getRepository(repositoryName)
        assertNotNull(updated)
        assertEquals(4, updated.naisTeams.size)
        assertTrue(updated.updatedAt.isAfter(initial.updatedAt) || updated.updatedAt == initial.updatedAt)

        val updatedVulns = repository.getVulnerabilities(repositoryName)
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
            repositoryName = "navikt/no-vulns-${System.currentTimeMillis()}",
            naisTeams = listOf("team-a"),
            vulnerabilities = emptyList()
        )

        repository.upsertRepositoryData(message)
        val vulnerabilities = repository.getVulnerabilities(message.repositoryName)
        assertEquals(0, vulnerabilities.size)
    }
}
