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
}

