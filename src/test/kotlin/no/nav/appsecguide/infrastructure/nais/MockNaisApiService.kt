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
}

