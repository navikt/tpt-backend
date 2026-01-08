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

    private val applicationsForUserQuery = this::class.java.classLoader
        .getResource("graphql/applications-for-user.graphql")
        ?.readText()
        ?: error("Could not load applications-for-user.graphql")

    private val vulnerabilitiesForUserQuery = this::class.java.classLoader
        .getResource("graphql/vulnerabilities-for-user.graphql")
        ?.readText()
        ?: error("Could not load vulnerabilities-for-user.graphql")

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

    private suspend fun paginateWorkloadVulnerabilities(
        email: String,
        teamCursor: String?,
        workload: VulnerabilitiesForUserResponse.WorkloadNode
    ): VulnerabilitiesForUserResponse.WorkloadNode {
        if (workload.image == null) {
            return workload
        }

        val allVulnerabilities = mutableListOf<VulnerabilitiesForUserResponse.Vulnerability>()
        var vulnCursor: String?
        var hasMoreVulns: Boolean

        allVulnerabilities.addAll(workload.image.vulnerabilities.nodes)
        vulnCursor = workload.image.vulnerabilities.pageInfo.endCursor
        hasMoreVulns = workload.image.vulnerabilities.pageInfo.hasNextPage

        while (hasMoreVulns) {
            val vulnRequest = VulnerabilitiesForUserRequest(
                query = vulnerabilitiesForUserQuery,
                variables = VulnerabilitiesForUserRequest.Variables(
                    email = email,
                    teamFirst = 1,
                    teamAfter = teamCursor,
                    workloadFirst = 50,
                    workloadAfter = null,
                    vulnFirst = 50,
                    vulnAfter = vulnCursor
                )
            )

            val vulnResponse = try {
                httpClient.post(apiUrl) {
                    contentType(ContentType.Application.Json)
                    bearerAuth(token)
                    setBody(vulnRequest)
                }
            } catch (e: Exception) {
                logger.error("HTTP error fetching vulnerabilities for workload ${workload.id}", e)
                break
            }

            val vulnPageResponse: VulnerabilitiesForUserResponse = vulnResponse.body()

            if (!vulnPageResponse.errors.isNullOrEmpty()) {
                logger.error("GraphQL errors fetching vulnerabilities for workload ${workload.id}: ${vulnPageResponse.errors.joinToString { "${it.message} at ${it.path}" }}")
                break
            }

            val paginatedWorkload = vulnPageResponse.data?.user?.teams?.nodes
                ?.firstOrNull()?.team?.workloads?.nodes
                ?.firstOrNull { it.id == workload.id }

            if (paginatedWorkload?.image != null) {
                allVulnerabilities.addAll(paginatedWorkload.image.vulnerabilities.nodes)
                hasMoreVulns = paginatedWorkload.image.vulnerabilities.pageInfo.hasNextPage
                vulnCursor = paginatedWorkload.image.vulnerabilities.pageInfo.endCursor
            } else {
                break
            }
        }

        return VulnerabilitiesForUserResponse.WorkloadNode(
            id = workload.id,
            name = workload.name,
            deployments = workload.deployments,
            image = VulnerabilitiesForUserResponse.Image(
                name = workload.image.name,
                tag = workload.image.tag,
                vulnerabilities = VulnerabilitiesForUserResponse.Vulnerabilities(
                    pageInfo = VulnerabilitiesForUserResponse.PageInfo(
                        hasNextPage = false,
                        endCursor = null
                    ),
                    nodes = allVulnerabilities
                )
            )
        )
    }

    suspend fun getVulnerabilitiesForUser(email: String): VulnerabilitiesForUserResponse {
        val allTeams = mutableListOf<VulnerabilitiesForUserResponse.TeamNode>()
        var teamCursor: String? = null
        var hasMoreTeams = true

        while (hasMoreTeams) {
            val request = VulnerabilitiesForUserRequest(
                query = vulnerabilitiesForUserQuery,
                variables = VulnerabilitiesForUserRequest.Variables(
                    email = email,
                    teamFirst = 1,
                    teamAfter = teamCursor,
                    workloadFirst = 50,
                    workloadAfter = null,
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
                logger.error("HTTP error fetching vulnerabilities for user $email", e)
                throw e
            }

            val pageResponse: VulnerabilitiesForUserResponse = response.body()

            if (!pageResponse.errors.isNullOrEmpty()) {
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
                val teamSlug = teamNode.team.slug
                val allWorkloads = mutableListOf<VulnerabilitiesForUserResponse.WorkloadNode>()
                var workloadCursor: String?
                var hasMoreWorkloads: Boolean

                // Process initial workloads from first team request
                val initialWorkloads = teamNode.team.workloads.nodes.map { workload ->
                    paginateWorkloadVulnerabilities(email, teamCursor, workload)
                }
                allWorkloads.addAll(initialWorkloads)

                workloadCursor = teamNode.team.workloads.pageInfo.endCursor
                hasMoreWorkloads = teamNode.team.workloads.pageInfo.hasNextPage

                while (hasMoreWorkloads) {
                    val workloadRequest = VulnerabilitiesForUserRequest(
                        query = vulnerabilitiesForUserQuery,
                        variables = VulnerabilitiesForUserRequest.Variables(
                            email = email,
                            teamFirst = 1,
                            teamAfter = teamCursor,
                            workloadFirst = 50,
                            workloadAfter = workloadCursor,
                            vulnFirst = 50
                        )
                    )

                    val workloadResponse = try {
                        httpClient.post(apiUrl) {
                            contentType(ContentType.Application.Json)
                            bearerAuth(token)
                            setBody(workloadRequest)
                        }
                    } catch (e: Exception) {
                        logger.error("HTTP error fetching workloads for team $teamSlug", e)
                        throw e
                    }

                    val workloadPageResponse: VulnerabilitiesForUserResponse = workloadResponse.body()

                    if (!workloadPageResponse.errors.isNullOrEmpty()) {
                        logger.error("GraphQL errors fetching workloads for team $teamSlug: ${workloadPageResponse.errors.joinToString { "${it.message} at ${it.path}" }}")
                        break
                    }

                    val workloadTeamNode = workloadPageResponse.data?.user?.teams?.nodes?.firstOrNull()
                    if (workloadTeamNode != null) {
                        val paginatedWorkloads = workloadTeamNode.team.workloads.nodes.map { workload ->
                            paginateWorkloadVulnerabilities(email, teamCursor, workload)
                        }
                        allWorkloads.addAll(paginatedWorkloads)
                        hasMoreWorkloads = workloadTeamNode.team.workloads.pageInfo.hasNextPage
                        workloadCursor = workloadTeamNode.team.workloads.pageInfo.endCursor
                    } else {
                        break
                    }
                }

                allTeams.add(
                    VulnerabilitiesForUserResponse.TeamNode(
                        team = VulnerabilitiesForUserResponse.Team(
                            slug = teamSlug,
                            workloads = VulnerabilitiesForUserResponse.Workloads(
                                pageInfo = VulnerabilitiesForUserResponse.PageInfo(
                                    hasNextPage = false,
                                    endCursor = null
                                ),
                                nodes = allWorkloads
                            )
                        )
                    )
                )
            }

            hasMoreTeams = teams.pageInfo.hasNextPage
            teamCursor = teams.pageInfo.endCursor
        }

        return VulnerabilitiesForUserResponse(
            data = VulnerabilitiesForUserResponse.Data(
                user = VulnerabilitiesForUserResponse.User(
                    teams = VulnerabilitiesForUserResponse.Teams(
                        pageInfo = VulnerabilitiesForUserResponse.PageInfo(
                            hasNextPage = false,
                            endCursor = null
                        ),
                        nodes = allTeams
                    )
                )
            )
        )
    }
}
