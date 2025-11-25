package no.nav.tpt.infrastructure.nais

class MockNaisApiService(
    private val shouldSucceed: Boolean = true,
    private val mockTeamApplicationsData: TeamApplicationsData? = null,
    private val mockUserApplicationsData: UserApplicationsData? = null,
    private val mockTeamVulnerabilitiesData: TeamVulnerabilitiesData? = null,
    private val mockUserVulnerabilitiesData: UserVulnerabilitiesData? = null
) : NaisApiService {

    override suspend fun getApplicationsForTeam(teamSlug: String): TeamApplicationsData {
        if (!shouldSucceed) {
            throw RuntimeException("Mock error: Failed to fetch applications for team")
        }

        return mockTeamApplicationsData ?: TeamApplicationsData(
            teamSlug = teamSlug,
            applications = listOf(
                ApplicationData(
                    name = "test-app",
                    ingressTypes = listOf(IngressType.INTERNAL)
                )
            )
        )
    }

    override suspend fun getApplicationsForUser(email: String): UserApplicationsData {
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
                            ingressTypes = listOf(IngressType.INTERNAL)
                        )
                    )
                )
            )
        )
    }

    override suspend fun getVulnerabilitiesForTeam(teamSlug: String): TeamVulnerabilitiesData {
        if (!shouldSucceed) {
            throw RuntimeException("Mock error: Failed to fetch vulnerabilities for team")
        }

        return mockTeamVulnerabilitiesData ?: TeamVulnerabilitiesData(
            teamSlug = teamSlug,
            workloads = listOf(
                WorkloadData(
                    id = "test-workload-id",
                    name = "test-workload",
                    imageTag = "2025.11.20-06.22-4c8872c",
                    vulnerabilities = listOf(
                        VulnerabilityData(
                            identifier = "CVE-2023-12345",
                            severity = "HIGH",
                            suppressed = false
                        )
                    )
                )
            )
        )
    }

    override suspend fun getVulnerabilitiesForUser(email: String): UserVulnerabilitiesData {
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
                            vulnerabilities = listOf(
                                VulnerabilityData(
                                    identifier = "CVE-2023-12345",
                                    severity = "HIGH",
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
