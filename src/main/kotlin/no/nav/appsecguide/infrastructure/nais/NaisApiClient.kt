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

    private val applicationsForTeamQuery = this::class.java.classLoader
        .getResource("graphql/applications-for-team.graphql")
        ?.readText()
        ?: error("Could not load applications-for-team.graphql")

    private val applicationsForUserQuery = this::class.java.classLoader
        .getResource("graphql/applications-for-user.graphql")
        ?.readText()
        ?: error("Could not load applications-for-user.graphql")

    private val vulnerabilitiesForTeamQuery = this::class.java.classLoader
        .getResource("graphql/vulnerabilities-for-team.graphql")
        ?.readText()
        ?: error("Could not load vulnerabilities-for-team.graphql")

    private val vulnerabilitiesForUserQuery = this::class.java.classLoader
        .getResource("graphql/vulnerabilities-for-user.graphql")
        ?.readText()
        ?: error("Could not load vulnerabilities-for-user.graphql")

    private fun createApplicationsForTeamRequest(teamSlug: String, cursor: String? = null): ApplicationsForTeamRequest {
        return ApplicationsForTeamRequest(
            query = applicationsForTeamQuery,
            variables = ApplicationsForTeamRequest.Variables(
                teamSlug = teamSlug,
                appFirst = 100,
                appAfter = cursor
            )
        )
    }

    override suspend fun getApplicationsForTeam(teamSlug: String): ApplicationsForTeamResponse {
        val allNodes = mutableListOf<ApplicationsForTeamResponse.Application>()
        var cursor: String? = null
        var hasNextPage = true

        while (hasNextPage) {
            val request = createApplicationsForTeamRequest(teamSlug, cursor)

            val response = httpClient.post(apiUrl) {
                contentType(ContentType.Application.Json)
                bearerAuth(token)
                setBody(request)
            }

            val pageResponse: ApplicationsForTeamResponse = response.body()

            if (pageResponse.errors != null && pageResponse.errors.isNotEmpty()) {
                return pageResponse
            }

            if (pageResponse.data?.team == null) {
                return ApplicationsForTeamResponse(
                    errors = listOf(
                        ApplicationsForTeamResponse.GraphQLError(
                            message = "Team not found or no data returned",
                            path = listOf("team")
                        )
                    )
                )
            }

            val applications = pageResponse.data.team.applications
            allNodes.addAll(applications.nodes)

            hasNextPage = applications.pageInfo.hasNextPage
            cursor = applications.pageInfo.endCursor
        }

        return ApplicationsForTeamResponse(
            data = ApplicationsForTeamResponse.Data(
                team = ApplicationsForTeamResponse.Team(
                    applications = ApplicationsForTeamResponse.Applications(
                        pageInfo = ApplicationsForTeamResponse.PageInfo(
                            hasNextPage = false,
                            endCursor = null
                        ),
                        nodes = allNodes
                    )
                )
            )
        )
    }

    private fun createApplicationsForUserRequest(email: String, cursor: String? = null): ApplicationsForUserRequest {
        return ApplicationsForUserRequest(
            query = applicationsForUserQuery,
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
                    val mergedNodes = existingTeamNode.team.applications.nodes + teamNode.team.applications.nodes
                    allTeamNodes.remove(existingTeamNode)
                    allTeamNodes.add(
                        ApplicationsForUserResponse.TeamNode(
                            team = ApplicationsForUserResponse.Team(
                                slug = teamNode.team.slug,
                                applications = ApplicationsForUserResponse.Applications(
                                    pageInfo = teamNode.team.applications.pageInfo,
                                    nodes = mergedNodes
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
                        nodes = teamNode.team.applications.nodes
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

    override suspend fun getVulnerabilitiesForTeam(teamSlug: String): VulnerabilitiesForTeamResponse {
        val request = VulnerabilitiesForTeamRequest(
            query = vulnerabilitiesForTeamQuery,
            variables = VulnerabilitiesForTeamRequest.Variables(
                teamSlug = teamSlug,
                workloadFirst = 50,
                vulnFirst = 50
            )
        )

        val response = httpClient.post(apiUrl) {
            contentType(ContentType.Application.Json)
            bearerAuth(token)
            setBody(request)
        }

        return response.body()
    }

    override suspend fun getVulnerabilitiesForUser(email: String): VulnerabilitiesForUserResponse {
        val allTeamNodes = mutableListOf<VulnerabilitiesForUserResponse.TeamNode>()
        var workloadCursor: String? = null
        var hasNextPage = true

        while (hasNextPage) {
            val request = VulnerabilitiesForUserRequest(
                query = vulnerabilitiesForUserQuery,
                variables = VulnerabilitiesForUserRequest.Variables(
                    email = email,
                    workloadFirst = 50,
                    workloadAfter = workloadCursor,
                    vulnFirst = 100
                )
            )

            val response = httpClient.post(apiUrl) {
                contentType(ContentType.Application.Json)
                bearerAuth(token)
                setBody(request)
            }

            val pageResponse: VulnerabilitiesForUserResponse = response.body()

            if (pageResponse.errors != null && pageResponse.errors.isNotEmpty()) {
                return pageResponse
            }

            if (pageResponse.data?.user == null) {
                return VulnerabilitiesForUserResponse(
                    errors = listOf(
                        VulnerabilitiesForUserResponse.GraphQLError(
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
                    val mergedWorkloads = existingTeamNode.team.workloads.nodes + teamNode.team.workloads.nodes
                    allTeamNodes.remove(existingTeamNode)
                    allTeamNodes.add(
                        VulnerabilitiesForUserResponse.TeamNode(
                            team = VulnerabilitiesForUserResponse.Team(
                                slug = teamNode.team.slug,
                                workloads = VulnerabilitiesForUserResponse.Workloads(
                                    pageInfo = teamNode.team.workloads.pageInfo,
                                    nodes = mergedWorkloads
                                )
                            )
                        )
                    )
                } else {
                    allTeamNodes.add(teamNode)
                }

                hasNextPage = teamNode.team.workloads.pageInfo.hasNextPage
                workloadCursor = teamNode.team.workloads.pageInfo.endCursor
            }

            if (!hasNextPage) break
        }

        val finalTeamNodes = allTeamNodes.map { teamNode ->
            VulnerabilitiesForUserResponse.TeamNode(
                team = VulnerabilitiesForUserResponse.Team(
                    slug = teamNode.team.slug,
                    workloads = VulnerabilitiesForUserResponse.Workloads(
                        pageInfo = VulnerabilitiesForUserResponse.PageInfo(
                            hasNextPage = false,
                            endCursor = null
                        ),
                        nodes = teamNode.team.workloads.nodes
                    )
                )
            )
        }

        return VulnerabilitiesForUserResponse(
            data = VulnerabilitiesForUserResponse.Data(
                user = VulnerabilitiesForUserResponse.User(
                    teams = VulnerabilitiesForUserResponse.Teams(
                        nodes = finalTeamNodes
                    )
                )
            )
        )
    }
}
