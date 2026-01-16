package no.nav.tpt.infrastructure.nais

class MockNaisApiService(
    private val shouldSucceed: Boolean = true,
    private val mockUserVulnerabilitiesData: UserVulnerabilitiesData? = null
) : NaisApiService {

    override suspend fun getVulnerabilitiesForUser(email: String, bypassCache: Boolean): UserVulnerabilitiesData {
        if (!shouldSucceed) {
            throw RuntimeException("Mock error: Failed to fetch vulnerabilities for user")
        }

        return mockUserVulnerabilitiesData ?: UserVulnerabilitiesData(
            teams = listOf(
                TeamVulnerabilitiesData(
                    teamSlug = "team-lokal-utvikler",
                    workloads = listOf(
                        WorkloadData(
                            id = "workload-1",
                            name = "app-lokal-utvikler",
                            workloadType = "app",
                            imageTag = "2026.01.13-10.30-abc123",
                            repository = "ghcr.io/navikt/app-lokal-utvikler",
                            vulnerabilities = listOf(
                                VulnerabilityData(
                                    identifier = "CVE-2023-12345",
                                    severity = "CRITICAL",
                                    packageName = "test-package",
                                    description = "A critical vulnerability in test package allowing remote code execution",
                                    vulnerabilityDetailsLink = "https://example.com/CVE-2023-12345",
                                    suppressed = false
                                ),
                                VulnerabilityData(
                                    identifier = "CVE-2023-54321",
                                    severity = "HIGH",
                                    packageName = "auth-library",
                                    description = "High severity authentication bypass vulnerability",
                                    vulnerabilityDetailsLink = "https://example.com/CVE-2023-54321",
                                    suppressed = false
                                ),
                                VulnerabilityData(
                                    identifier = "CVE-2024-11111",
                                    severity = "MEDIUM",
                                    packageName = "database-connector",
                                    description = "Medium severity SQL injection vulnerability",
                                    vulnerabilityDetailsLink = "https://example.com/CVE-2024-11111",
                                    suppressed = false
                                )
                            ),
                            environment = "production",
                            ingressTypes = emptyList()
                        )
                    )
                )
            )
        )
    }

    override suspend fun getVulnerabilitiesForTeam(teamSlug: String, bypassCache: Boolean): UserVulnerabilitiesData {
        if (!shouldSucceed) {
            throw RuntimeException("Mock error: Failed to fetch vulnerabilities for team")
        }

        return mockUserVulnerabilitiesData ?: UserVulnerabilitiesData(
            teams = listOf(
                TeamVulnerabilitiesData(
                    teamSlug = teamSlug,
                    workloads = listOf(
                        WorkloadData(
                            id = "workload-1",
                            name = "app-${teamSlug}",
                            workloadType = "app",
                            imageTag = "2026.01.13-10.30-abc123",
                            repository = "ghcr.io/navikt/app-${teamSlug}",
                            vulnerabilities = listOf(
                                VulnerabilityData(
                                    identifier = "CVE-2023-12345",
                                    severity = "CRITICAL",
                                    packageName = "test-package",
                                    description = "A critical vulnerability in test package allowing remote code execution",
                                    vulnerabilityDetailsLink = "https://example.com/CVE-2023-12345",
                                    suppressed = false
                                )
                            ),
                            environment = "production",
                            ingressTypes = emptyList()
                        )
                    )
                )
            )
        )
    }
}
