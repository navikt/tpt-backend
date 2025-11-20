package no.nav.appsecguide.infrastructure.nais

class MockNaisApiService(
    private val shouldSucceed: Boolean = true,
    private val mockResponse: TeamIngressTypesResponse? = null,
    private val mockUserResponse: ApplicationsForUserResponse? = null
) : NaisApiService {

    override suspend fun getTeamIngressTypes(teamSlug: String): TeamIngressTypesResponse {
        if (!shouldSucceed) {
            return TeamIngressTypesResponse(
                errors = listOf(
                    TeamIngressTypesResponse.GraphQLError(
                        message = "Mock error",
                        path = listOf("team")
                    )
                )
            )
        }

        return mockResponse ?: TeamIngressTypesResponse(
            data = TeamIngressTypesResponse.Data(
                team = TeamIngressTypesResponse.Team(
                    applications = TeamIngressTypesResponse.Applications(
                        pageInfo = TeamIngressTypesResponse.PageInfo(
                            hasNextPage = false,
                            endCursor = null
                        ),
                        edges = listOf(
                            TeamIngressTypesResponse.Edge(
                                node = TeamIngressTypesResponse.Application(
                                    name = "test-app",
                                    ingresses = listOf(
                                        TeamIngressTypesResponse.Ingress(type = "internal")
                                    )
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
                                        edges = listOf(
                                            ApplicationsForUserResponse.Edge(
                                                node = ApplicationsForUserResponse.Application(
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
        )
    }
}

