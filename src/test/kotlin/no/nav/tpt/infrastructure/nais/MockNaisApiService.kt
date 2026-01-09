package no.nav.tpt.infrastructure.nais

class MockNaisApiService(
    private val shouldSucceed: Boolean = true,
    private val mockUserApplicationsData: UserApplicationsData? = null,
    private val mockUserVulnerabilitiesData: UserVulnerabilitiesData? = null
) : NaisApiService {

    override suspend fun getApplicationsForUser(email: String, bypassCache: Boolean): UserApplicationsData {
        if (!shouldSucceed) {
            throw RuntimeException("Mock error: Failed to fetch applications for user")
        }

        if (mockUserApplicationsData != null) {
            return mockUserApplicationsData
        }

        val teamSlug = "team-${email.substringBefore("@")}"
        val appName = "app-${email.substringBefore("@")}"

        return UserApplicationsData(
            teams = listOf(
                TeamApplicationsData(
                    teamSlug = teamSlug,
                    applications = listOf(
                        ApplicationData(
                            name = appName,
                            ingressTypes = listOf(IngressType.INTERNAL),
                            environment = null
                        )
                    )
                )
            )
        )
    }

    override suspend fun getVulnerabilitiesForUser(email: String, bypassCache: Boolean): UserVulnerabilitiesData {
        if (!shouldSucceed) {
            throw RuntimeException("Mock error: Failed to fetch vulnerabilities for user")
        }

        return mockUserVulnerabilitiesData ?: UserVulnerabilitiesData(
            teams = listOf(
                TeamVulnerabilitiesData(
                    teamSlug = "test-team",
                    workloads = listOf(
                        WorkloadData(
                            id = "test-workload-id",
                            name = "test-workload",
                            imageTag = "2025.11.20-06.22-4c8872c",
                            repository = null,
                            vulnerabilities = listOf(
                                VulnerabilityData(
                                    identifier = "CVE-2023-12345",
                                    severity = "HIGH",
                                    packageName = null,
                                    description = null,
                                    vulnerabilityDetailsLink = null,
                                    suppressed = false
                                )
                            )
                        )
                    )
                )
            )
        )
    }
}
