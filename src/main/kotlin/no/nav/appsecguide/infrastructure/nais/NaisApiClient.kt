package no.nav.appsecguide.infrastructure.nais

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*

class NaisApiClient(
    private val httpClient: HttpClient,
    private val apiUrl: String,
    private val token: String
) : NaisApiService {

    private val teamIngressQuery = this::class.java.classLoader
        .getResource("graphql/team-ingress.graphql")
        ?.readText()
        ?: error("Could not load team-ingress.graphql")

    private val applicationsForUser = this::class.java.classLoader
        .getResource("graphql/applications-for-user.graphql")
        ?.readText()
        ?: error("Could not load applications-for-user.graphql")

    private fun createTeamIngressTypesRequest(teamSlug: String, cursor: String? = null): TeamIngressTypesRequest {
        return TeamIngressTypesRequest(
            query = teamIngressQuery,
            variables = TeamIngressTypesRequest.Variables(
                teamSlug = teamSlug,
                appFirst = 100,
                appAfter = cursor
            )
        )
    }

    override suspend fun getTeamIngressTypes(teamSlug: String): TeamIngressTypesResponse {
        val allEdges = mutableListOf<TeamIngressTypesResponse.Edge>()
        var cursor: String? = null
        var hasNextPage = true

        while (hasNextPage) {
            val request = createTeamIngressTypesRequest(teamSlug, cursor)

            val response = httpClient.post(apiUrl) {
                contentType(ContentType.Application.Json)
                bearerAuth(token)
                setBody(request)
            }

            val pageResponse: TeamIngressTypesResponse = response.body()

            if (pageResponse.errors != null && pageResponse.errors.isNotEmpty()) {
                return pageResponse
            }

            if (pageResponse.data?.team == null) {
                return TeamIngressTypesResponse(
                    errors = listOf(
                        TeamIngressTypesResponse.GraphQLError(
                            message = "Team not found or no data returned",
                            path = listOf("team")
                        )
                    )
                )
            }

            val applications = pageResponse.data.team.applications
            allEdges.addAll(applications.edges)

            hasNextPage = applications.pageInfo.hasNextPage
            cursor = applications.pageInfo.endCursor
        }

        return TeamIngressTypesResponse(
            data = TeamIngressTypesResponse.Data(
                team = TeamIngressTypesResponse.Team(
                    applications = TeamIngressTypesResponse.Applications(
                        pageInfo = TeamIngressTypesResponse.PageInfo(
                            hasNextPage = false,
                            endCursor = null
                        ),
                        edges = allEdges
                    )
                )
            )
        )
    }

    private fun createApplicationsForUserRequest(email: String, cursor: String? = null): ApplicationsForUserRequest {
        return ApplicationsForUserRequest(
            query = applicationsForUser,
            variables = ApplicationsForUserRequest.Variables(
                email = email,
                appFirst = 100,
                appAfter = cursor
            )
        )
    }

    override suspend fun getApplicationsForUser(email: String): ApplicationsForUserResponse {
        val allTeamNodes = mutableListOf<ApplicationsForUserResponse.TeamNode>()
        var cursor: String? = null
        var hasNextPage = true

        while (hasNextPage) {
            val request = createApplicationsForUserRequest(email, cursor)

            val response = httpClient.post(apiUrl) {
                contentType(ContentType.Application.Json)
                bearerAuth(token)
                setBody(request)
            }

            val pageResponse: ApplicationsForUserResponse = response.body()

            if (pageResponse.errors != null && pageResponse.errors.isNotEmpty()) {
                return pageResponse
            }

            if (pageResponse.data?.user == null) {
                return ApplicationsForUserResponse(
                    errors = listOf(
                        ApplicationsForUserResponse.GraphQLError(
                            message = "User not found or no data returned",
                            path = listOf("user")
                        )
                    )
                )
            }

            val teams = pageResponse.data.user.teams
            for (teamNode in teams.nodes) {
                val existingTeamNode = allTeamNodes.find { it.team.slug == teamNode.team.slug }
                if (existingTeamNode != null) {
                    val mergedEdges = existingTeamNode.team.applications.edges + teamNode.team.applications.edges
                    allTeamNodes.remove(existingTeamNode)
                    allTeamNodes.add(
                        ApplicationsForUserResponse.TeamNode(
                            team = ApplicationsForUserResponse.Team(
                                slug = teamNode.team.slug,
                                applications = ApplicationsForUserResponse.Applications(
                                    pageInfo = teamNode.team.applications.pageInfo,
                                    edges = mergedEdges
                                )
                            )
                        )
                    )
                } else {
                    allTeamNodes.add(teamNode)
                }

                hasNextPage = teamNode.team.applications.pageInfo.hasNextPage
                cursor = teamNode.team.applications.pageInfo.endCursor
            }

            if (!hasNextPage) break
        }

        val finalTeamNodes = allTeamNodes.map { teamNode ->
            ApplicationsForUserResponse.TeamNode(
                team = ApplicationsForUserResponse.Team(
                    slug = teamNode.team.slug,
                    applications = ApplicationsForUserResponse.Applications(
                        pageInfo = ApplicationsForUserResponse.PageInfo(
                            hasNextPage = false,
                            endCursor = null
                        ),
                        edges = teamNode.team.applications.edges
                    )
                )
            )
        }

        return ApplicationsForUserResponse(
            data = ApplicationsForUserResponse.Data(
                user = ApplicationsForUserResponse.User(
                    teams = ApplicationsForUserResponse.Teams(
                        nodes = finalTeamNodes
                    )
                )
            )
        )
    }
}

