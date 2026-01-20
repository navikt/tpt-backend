package no.nav.tpt.infrastructure.github

import no.nav.tpt.infrastructure.kafka.GitHubRepositoryMessage
import java.time.Instant

class MockGitHubRepositoryWithData : GitHubRepository {

    private val mockRepositories = listOf(
        GitHubRepositoryData(
            repositoryName = "navikt/tpt-backend",
            naisTeams = listOf("appsec"),
            createdAt = Instant.parse("2024-01-15T10:00:00Z"),
            updatedAt = Instant.parse("2024-12-20T14:30:00Z")
        ),
        GitHubRepositoryData(
            repositoryName = "navikt/security-tools",
            naisTeams = listOf("appsec", "platform"),
            createdAt = Instant.parse("2023-06-10T08:00:00Z"),
            updatedAt = Instant.parse("2024-12-18T09:15:00Z")
        ),
        GitHubRepositoryData(
            repositoryName = "navikt/example-app",
            naisTeams = listOf("team-rocket"),
            createdAt = Instant.parse("2024-03-01T12:00:00Z"),
            updatedAt = Instant.parse("2024-12-15T16:45:00Z")
        )
    )

    private val mockVulnerabilities = mapOf(
        "navikt/tpt-backend" to listOf(
            GitHubVulnerabilityData(
                id = 1,
                repositoryName = "navikt/tpt-backend",
                severity = "HIGH",
                identifiers = listOf(
                    GitHubIdentifierData(value = "CVE-2024-12345", type = "CVE"),
                    GitHubIdentifierData(value = "GHSA-xxxx-yyyy-zzzz", type = "GHSA")
                ),
                createdAt = Instant.parse("2024-12-01T10:00:00Z"),
                updatedAt = Instant.parse("2024-12-01T10:00:00Z")
            ),
            GitHubVulnerabilityData(
                id = 2,
                repositoryName = "navikt/tpt-backend",
                severity = "MEDIUM",
                identifiers = listOf(
                    GitHubIdentifierData(value = "CVE-2024-23456", type = "CVE")
                ),
                createdAt = Instant.parse("2024-11-15T14:30:00Z"),
                updatedAt = Instant.parse("2024-11-15T14:30:00Z")
            )
        ),
        "navikt/security-tools" to listOf(
            GitHubVulnerabilityData(
                id = 3,
                repositoryName = "navikt/security-tools",
                severity = "CRITICAL",
                identifiers = listOf(
                    GitHubIdentifierData(value = "CVE-2024-34567", type = "CVE")
                ),
                createdAt = Instant.parse("2024-12-10T09:00:00Z"),
                updatedAt = Instant.parse("2024-12-10T09:00:00Z")
            ),
            GitHubVulnerabilityData(
                id = 4,
                repositoryName = "navikt/security-tools",
                severity = "LOW",
                identifiers = listOf(
                    GitHubIdentifierData(value = "CVE-2024-45678", type = "CVE")
                ),
                createdAt = Instant.parse("2024-10-20T11:20:00Z"),
                updatedAt = Instant.parse("2024-10-20T11:20:00Z")
            )
        ),
        "navikt/example-app" to listOf(
            GitHubVulnerabilityData(
                id = 5,
                repositoryName = "navikt/example-app",
                severity = "HIGH",
                identifiers = listOf(
                    GitHubIdentifierData(value = "CVE-2024-56789", type = "CVE")
                ),
                createdAt = Instant.parse("2024-11-25T16:00:00Z"),
                updatedAt = Instant.parse("2024-11-25T16:00:00Z")
            )
        )
    )

    override suspend fun upsertRepositoryData(message: GitHubRepositoryMessage) {
        // No-op for mock
    }

    override suspend fun getRepository(repositoryName: String): GitHubRepositoryData? {
        return mockRepositories.find { it.repositoryName == repositoryName }
    }

    override suspend fun getVulnerabilities(repositoryName: String): List<GitHubVulnerabilityData> {
        return mockVulnerabilities[repositoryName] ?: emptyList()
    }

    override suspend fun getAllRepositories(): List<GitHubRepositoryData> {
        return mockRepositories
    }

    override suspend fun getRepositoriesByTeams(teamSlugs: List<String>): List<GitHubRepositoryData> {
        return mockRepositories.filter { repo ->
            repo.naisTeams.any { it in teamSlugs }
        }
    }
}
