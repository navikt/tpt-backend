package no.nav.tpt.infrastructure.nais

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import org.slf4j.LoggerFactory

class NaisApiClient(
    private val httpClient: HttpClient,
    private val apiUrl: String,
    private val token: String
) {
    private val logger = LoggerFactory.getLogger(NaisApiClient::class.java)

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

    suspend fun getApplicationsForTeam(teamSlug: String): ApplicationsForTeamResponse {
        val allNodes = mutableListOf<ApplicationsForTeamResponse.Application>()
        var cursor: String? = null
        var hasNextPage = true

        while (hasNextPage) {
            val request = createApplicationsForTeamRequest(teamSlug, cursor)

            val response = try {
                httpClient.post(apiUrl) {
                    contentType(ContentType.Application.Json)
                    bearerAuth(token)
                    setBody(request)
                }
            } catch (e: Exception) {
                logger.error("HTTP error fetching applications for team $teamSlug", e)
                throw e
            }

            val pageResponse: ApplicationsForTeamResponse = response.body()

            if (pageResponse.errors != null && pageResponse.errors.isNotEmpty()) {
                logger.error("GraphQL errors for team $teamSlug: ${pageResponse.errors.joinToString { "${it.message} at ${it.path}" }}")
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

    suspend fun getApplicationsForUser(email: String): ApplicationsForUserResponse {
        val allTeamNodes = mutableListOf<ApplicationsForUserResponse.TeamNode>()
        var cursor: String? = null
        var hasNextPage = true

        while (hasNextPage) {
            val request = createApplicationsForUserRequest(email, cursor)

            val response = try {
                httpClient.post(apiUrl) {
                    contentType(ContentType.Application.Json)
                    bearerAuth(token)
                    setBody(request)
                }
            } catch (e: Exception) {
                logger.error("HTTP error fetching applications for user $email", e)
                throw e
            }

            val pageResponse: ApplicationsForUserResponse = response.body()

            if (pageResponse.errors != null && pageResponse.errors.isNotEmpty()) {
                logger.error("GraphQL errors for user $email: ${pageResponse.errors.joinToString { "${it.message} at ${it.path}" }}")
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

    suspend fun getVulnerabilitiesForTeam(teamSlug: String): VulnerabilitiesForTeamResponse {
        val request = VulnerabilitiesForTeamRequest(
            query = vulnerabilitiesForTeamQuery,
            variables = VulnerabilitiesForTeamRequest.Variables(
                teamSlug = teamSlug,
                workloadFirst = 50,
                vulnFirst = 50
            )
        )

        val response = try {
            httpClient.post(apiUrl) {
                contentType(ContentType.Application.Json)
                bearerAuth(token)
                setBody(request)
            }
        } catch (e: Exception) {
            logger.error("HTTP error fetching vulnerabilities for team $teamSlug", e)
            throw e
        }

        val result: VulnerabilitiesForTeamResponse = response.body()

        if (result.errors != null && result.errors.isNotEmpty()) {
            logger.error("GraphQL errors for team vulnerabilities $teamSlug: ${result.errors.joinToString { "${it.message} at ${it.path}" }}")
        }

        return result
    }

    suspend fun getVulnerabilitiesForUser(email: String): VulnerabilitiesForUserResponse {
        val allTeamNodes = mutableListOf<VulnerabilitiesForUserResponse.TeamNode>()
        var teamCursor: String? = null
        var hasMoreTeams = true

        while (hasMoreTeams) {
            val request = VulnerabilitiesForUserRequest(
                query = vulnerabilitiesForUserQuery,
                variables = VulnerabilitiesForUserRequest.Variables(
                    email = email,
                    teamFirst = 50,
                    teamAfter = teamCursor,
                    workloadFirst = 50,
                    vulnFirst = 100
                )
            )

            val response = try {
                httpClient.post(apiUrl) {
                    contentType(ContentType.Application.Json)
                    bearerAuth(token)
                    setBody(request)
                }
            } catch (e: Exception) {
                logger.error("HTTP error fetching vulnerabilities for user $email", e)
                throw e
            }

            val pageResponse: VulnerabilitiesForUserResponse = response.body()

            if (pageResponse.errors != null && pageResponse.errors.isNotEmpty()) {
                logger.error("GraphQL errors for user vulnerabilities $email: ${pageResponse.errors.joinToString { "${it.message} at ${it.path}" }}")
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
                val fullTeamNode = fetchAllWorkloadsForTeam(email, teamNode)
                allTeamNodes.add(fullTeamNode)
            }

            hasMoreTeams = teams.pageInfo.hasNextPage
            teamCursor = teams.pageInfo.endCursor
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
                        pageInfo = VulnerabilitiesForUserResponse.PageInfo(
                            hasNextPage = false,
                            endCursor = null
                        ),
                        nodes = finalTeamNodes
                    )
                )
            )
        )
    }

    private suspend fun fetchAllWorkloadsForTeam(
        email: String,
        initialTeamNode: VulnerabilitiesForUserResponse.TeamNode
    ): VulnerabilitiesForUserResponse.TeamNode {
        val allWorkloads = initialTeamNode.team.workloads.nodes.toMutableList()
        var workloadCursor = initialTeamNode.team.workloads.pageInfo.endCursor
        var hasMoreWorkloads = initialTeamNode.team.workloads.pageInfo.hasNextPage

        while (hasMoreWorkloads) {
            val request = VulnerabilitiesForUserRequest(
                query = vulnerabilitiesForUserQuery,
                variables = VulnerabilitiesForUserRequest.Variables(
                    email = email,
                    teamFirst = 1,
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
            val teamNode = pageResponse.data?.user?.teams?.nodes
                ?.find { it.team.slug == initialTeamNode.team.slug }

            if (teamNode != null) {
                allWorkloads.addAll(teamNode.team.workloads.nodes)
                hasMoreWorkloads = teamNode.team.workloads.pageInfo.hasNextPage
                workloadCursor = teamNode.team.workloads.pageInfo.endCursor
            } else {
                hasMoreWorkloads = false
            }
        }

        return VulnerabilitiesForUserResponse.TeamNode(
            team = VulnerabilitiesForUserResponse.Team(
                slug = initialTeamNode.team.slug,
                workloads = VulnerabilitiesForUserResponse.Workloads(
                    pageInfo = VulnerabilitiesForUserResponse.PageInfo(
                        hasNextPage = false,
                        endCursor = null
                    ),
                    nodes = allWorkloads
                )
            )
        )
    }
}
