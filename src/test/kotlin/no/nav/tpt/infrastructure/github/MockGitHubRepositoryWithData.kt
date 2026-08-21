package no.nav.tpt.infrastructure.github

import no.nav.tpt.infrastructure.github.GitHubRepositoryMessage
import java.time.Instant

class MockGitHubRepositoryWithData : GitHubRepository {

    private val mockRepositories = listOf(
        GitHubRepositoryData(
            nameWithOwner = "navikt/tpt-backend",
            naisTeams = listOf("team-lokal-utvikler"),
            usesDistroless = true,
            codeScanningStatus = "OK",
            createdAt = Instant.parse("2024-01-15T10:00:00Z"),
            updatedAt = Instant.parse("2024-12-20T14:30:00Z")
        ),
        GitHubRepositoryData(
            nameWithOwner = "navikt/security-tools",
            naisTeams = listOf("team-lokal-utvikler", "team-b"),
            usesDistroless = false,
            codeScanningStatus = "security-tools has no code scanning analyses, possibly no tools configured",
            createdAt = Instant.parse("2023-06-10T08:00:00Z"),
            updatedAt = Instant.parse("2024-12-18T09:15:00Z")
        ),
        GitHubRepositoryData(
            nameWithOwner = "navikt/example-app",
            naisTeams = listOf("team-c"),
            usesDistroless = null,
            codeScanningStatus = null,
            createdAt = Instant.parse("2024-03-01T12:00:00Z"),
            updatedAt = Instant.parse("2024-12-15T16:45:00Z")
        )
    )

    private val mockVulnerabilities = mapOf(
        "navikt/tpt-backend" to listOf(
            GitHubVulnerabilityData(
                id = 1,
                nameWithOwner = "navikt/tpt-backend",
                severity = "HIGH",
                identifiers = listOf(
                    GitHubIdentifierData(value = "CVE-2024-12345", type = "CVE"),
                    GitHubIdentifierData(value = "GHSA-xxxx-yyyy-zzzz", type = "GHSA")
                ),
                packageName = "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.2",
                packageEcosystem = "MAVEN",
                dependencyScope = "RUNTIME",
                cvssScore = 8.8,
                summary = "Deserialization of untrusted data allows remote code execution via gadget chains.",
                createdAt = Instant.parse("2024-12-01T10:00:00Z"),
                updatedAt = Instant.parse("2024-12-01T10:00:00Z")
            ),
            GitHubVulnerabilityData(
                id = 2,
                nameWithOwner = "navikt/tpt-backend",
                severity = "MEDIUM",
                identifiers = listOf(
                    GitHubIdentifierData(value = "CVE-2024-23456", type = "CVE")
                ),
                packageName = "pkg:maven/org.springframework/spring-core@6.1.3",
                packageEcosystem = "MAVEN",
                dependencyScope = "RUNTIME",
                cvssScore = 5.3,
                summary = "Improper input validation in Spring Framework allows denial of service.",
                createdAt = Instant.parse("2024-11-15T14:30:00Z"),
                updatedAt = Instant.parse("2024-11-15T14:30:00Z")
            )
        ),
        "navikt/security-tools" to listOf(
            GitHubVulnerabilityData(
                id = 3,
                nameWithOwner = "navikt/security-tools",
                severity = "CRITICAL",
                identifiers = listOf(
                    GitHubIdentifierData(value = "CVE-2024-34567", type = "CVE")
                ),
                packageName = "pkg:npm/express@4.18.2",
                packageEcosystem = "NPM",
                dependencyScope = "RUNTIME",
                cvssScore = 9.8,
                summary = "Buffer overflow in HTTP request parser allows remote code execution.",
                dependabotUpdatePullRequestUrl = "https://github.com/navikt/security-tools/pull/42",
                createdAt = Instant.parse("2024-12-10T09:00:00Z"),
                updatedAt = Instant.parse("2024-12-10T09:00:00Z")
            ),
            GitHubVulnerabilityData(
                id = 4,
                nameWithOwner = "navikt/security-tools",
                severity = "LOW",
                identifiers = listOf(
                    GitHubIdentifierData(value = "CVE-2024-45678", type = "CVE")
                ),
                packageName = "pkg:npm/semver@7.5.3",
                packageEcosystem = "NPM",
                dependencyScope = "DEVELOPMENT",
                cvssScore = 3.7,
                summary = "ReDoS vulnerability when parsing untrusted version strings.",
                createdAt = Instant.parse("2024-10-20T11:20:00Z"),
                updatedAt = Instant.parse("2024-10-20T11:20:00Z")
            )
        ),
        "navikt/example-app" to listOf(
            GitHubVulnerabilityData(
                id = 5,
                nameWithOwner = "navikt/example-app",
                severity = "HIGH",
                identifiers = listOf(
                    GitHubIdentifierData(value = "CVE-2024-56789", type = "CVE")
                ),
                packageName = "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
                packageEcosystem = "GO",
                dependencyScope = "RUNTIME",
                cvssScore = 7.5,
                summary = "Path traversal in static file serving allows reading arbitrary files.",
                createdAt = Instant.parse("2024-11-25T16:00:00Z"),
                updatedAt = Instant.parse("2024-11-25T16:00:00Z")
            )
        )
    )

    override suspend fun upsertRepositoryData(message: GitHubRepositoryMessage) {
        // No-op for mock
    }

    override suspend fun updateCodeScanningStatus(repoName: String, status: String) {
        // No-op for mock
    }

    override suspend fun getRepository(nameWithOwner: String): GitHubRepositoryData? {
        return mockRepositories.find { it.nameWithOwner == nameWithOwner }
    }

    override suspend fun getVulnerabilities(nameWithOwner: String): List<GitHubVulnerabilityData> {
        return mockVulnerabilities[nameWithOwner] ?: emptyList()
    }

    override suspend fun getAllRepositories(): List<GitHubRepositoryData> {
        return mockRepositories
    }

    override suspend fun getRepositoriesByTeams(teamSlugs: List<String>): List<GitHubRepositoryData> {
        return mockRepositories.filter { repo ->
            repo.naisTeams.any { it in teamSlugs }
        }
    }

    override suspend fun deleteRepositoriesExclusivelyOwnedBy(teamSlugs: List<String>) {
        // No-op for mock
    }

    override suspend fun removeTeamsFromSharedRepositories(teamSlugs: List<String>) {
        // No-op for mock
    }

    override suspend fun tryAcquireRefreshLock(teamSlug: String): Boolean = true

    override suspend fun releaseRefreshLock(teamSlug: String) {
        // No-op for mock
    }
}
