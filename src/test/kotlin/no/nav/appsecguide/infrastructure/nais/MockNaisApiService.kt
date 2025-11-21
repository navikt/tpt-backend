package no.nav.appsecguide.infrastructure.nais

class MockNaisApiService(
    private val shouldSucceed: Boolean = true,
    private val mockResponse: ApplicationsForTeamResponse? = null,
    private val mockUserResponse: ApplicationsForUserResponse? = null
) : NaisApiService {

    override suspend fun getApplicationsForTeam(teamSlug: String): ApplicationsForTeamResponse {
        if (!shouldSucceed) {
            return ApplicationsForTeamResponse(
                errors = listOf(
                    ApplicationsForTeamResponse.GraphQLError(
                        message = "Mock error",
                        path = listOf("team")
                    )
                )
            )
        }

        return mockResponse ?: ApplicationsForTeamResponse(
            data = ApplicationsForTeamResponse.Data(
                team = ApplicationsForTeamResponse.Team(
                    applications = ApplicationsForTeamResponse.Applications(
                        pageInfo = ApplicationsForTeamResponse.PageInfo(
                            hasNextPage = false,
                            endCursor = null
                        ),
                        nodes = listOf(
                            ApplicationsForTeamResponse.Application(
                                name = "test-app",
                                ingresses = listOf(
                                    ApplicationsForTeamResponse.Ingress(type = "internal")
                                )
                            )
                        )
                    )
                )
            )
        )
    }

    override suspend fun getApplicationsForUser(email: String): ApplicationsForUserResponse {
        if (!shouldSucceed) {
            return ApplicationsForUserResponse(
                errors = listOf(
                    ApplicationsForUserResponse.GraphQLError(
                        message = "Mock error",
                        path = listOf("user")
                    )
                )
            )
        }

        if (mockUserResponse != null) {
            return mockUserResponse
        }

        val teamSlug = "team-${email.substringBefore("@")}"
        val appName = "app-${email.substringBefore("@")}"

        return ApplicationsForUserResponse(
            data = ApplicationsForUserResponse.Data(
                user = ApplicationsForUserResponse.User(
                    teams = ApplicationsForUserResponse.Teams(
                        nodes = listOf(
                            ApplicationsForUserResponse.TeamNode(
                                team = ApplicationsForUserResponse.Team(
                                    slug = teamSlug,
                                    applications = ApplicationsForUserResponse.Applications(
                                        pageInfo = ApplicationsForUserResponse.PageInfo(
                                            hasNextPage = false,
                                            endCursor = null
                                        ),
                                        nodes = listOf(
                                            ApplicationsForUserResponse.Application(
                                                name = appName,
                                                ingresses = listOf(
                                                    ApplicationsForUserResponse.Ingress(type = "internal")
                                                )
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
        )
    }

    override suspend fun getVulnerabilitiesForTeam(teamSlug: String): VulnerabilitiesForTeamResponse {
        if (!shouldSucceed) {
            return VulnerabilitiesForTeamResponse(
                errors = listOf(
                    VulnerabilitiesForTeamResponse.GraphQLError(
                        message = "Mock error",
                        path = listOf("team")
                    )
                )
            )
        }

        return VulnerabilitiesForTeamResponse(
            data = VulnerabilitiesForTeamResponse.Data(
                team = VulnerabilitiesForTeamResponse.Team(
                    workloads = VulnerabilitiesForTeamResponse.Workloads(
                        pageInfo = VulnerabilitiesForTeamResponse.PageInfo(
                            hasNextPage = false,
                            endCursor = null
                        ),
                        nodes = listOf(
                            VulnerabilitiesForTeamResponse.WorkloadNode(
                                name = "test-workload",
                                image = VulnerabilitiesForTeamResponse.Image(
                                    vulnerabilities = VulnerabilitiesForTeamResponse.Vulnerabilities(
                                        pageInfo = VulnerabilitiesForTeamResponse.PageInfo(
                                            hasNextPage = false,
                                            endCursor = null
                                        ),
                                        nodes = listOf(
                                            VulnerabilitiesForTeamResponse.Vulnerability(
                                                identifier = "CVE-2023-12345",
                                                severity = "HIGH",
                                                suppression = null
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
        )
    }

    override suspend fun getVulnerabilitiesForUser(email: String): VulnerabilitiesForUserResponse {
        if (!shouldSucceed) {
            return VulnerabilitiesForUserResponse(
                errors = listOf(
                    VulnerabilitiesForUserResponse.GraphQLError(
                        message = "Mock error",
                        path = listOf("user")
                    )
                )
            )
        }

        return VulnerabilitiesForUserResponse(
            data = VulnerabilitiesForUserResponse.Data(
                user = VulnerabilitiesForUserResponse.User(
                    teams = VulnerabilitiesForUserResponse.Teams(
                        nodes = listOf(
                            VulnerabilitiesForUserResponse.TeamNode(
                                team = VulnerabilitiesForUserResponse.Team(
                                    slug = "test-team",
                                    workloads = VulnerabilitiesForUserResponse.Workloads(
                                        pageInfo = VulnerabilitiesForUserResponse.PageInfo(
                                            hasNextPage = false,
                                            endCursor = null
                                        ),
                                        nodes = listOf(
                                            VulnerabilitiesForUserResponse.WorkloadNode(
                                                name = "test-workload",
                                                image = VulnerabilitiesForUserResponse.Image(
                                                    vulnerabilities = VulnerabilitiesForUserResponse.Vulnerabilities(
                                                        pageInfo = VulnerabilitiesForUserResponse.PageInfo(
                                                            hasNextPage = false,
                                                            endCursor = null
                                                        ),
                                                        nodes = listOf(
                                                            VulnerabilitiesForUserResponse.Vulnerability(
                                                                identifier = "CVE-2023-12345",
                                                                severity = "HIGH",
                                                                suppression = null
                                                            )
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
        )
    }
}
