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
        .getResource("graphql/app-vulnerabilities-for-user.graphql")
        ?.readText()
        ?: error("Could not load app-vulnerabilities-for-user.graphql")

    private val jobVulnerabilitiesForUserQuery = this::class.java.classLoader
        .getResource("graphql/job-vulnerabilities-for-user.graphql")
        ?.readText()
        ?: error("Could not load job-vulnerabilities-for-user.graphql")

    suspend fun getVulnerabilitiesForUser(email: String): WorkloadVulnerabilitiesResponse {
        val appResponse = fetchWorkloadVulnerabilities(email, applicationsForUserQuery, "applications")
        val jobResponse = fetchWorkloadVulnerabilities(email, jobVulnerabilitiesForUserQuery, "jobs")

        if (!appResponse.errors.isNullOrEmpty() || !jobResponse.errors.isNullOrEmpty()) {
            val allErrors = (appResponse.errors ?: emptyList()) + (jobResponse.errors ?: emptyList())
            return WorkloadVulnerabilitiesResponse(errors = allErrors)
        }

        val mergedTeams = mergeWorkloadResponses(appResponse, jobResponse)

        return WorkloadVulnerabilitiesResponse(
            data = WorkloadVulnerabilitiesResponse.Data(
                user = WorkloadVulnerabilitiesResponse.User(
                    teams = WorkloadVulnerabilitiesResponse.Teams(
                        pageInfo = WorkloadVulnerabilitiesResponse.PageInfo(false, null),
                        nodes = mergedTeams
                    )
                )
            )
        )
    }

    private suspend fun fetchWorkloadVulnerabilities(
        email: String,
        query: String,
        workloadType: String
    ): WorkloadVulnerabilitiesResponse {
        val allTeams = mutableListOf<WorkloadVulnerabilitiesResponse.TeamNode>()
        var teamCursor: String? = null
        var hasMoreTeams = true

        while (hasMoreTeams) {
            val request = WorkloadVulnerabilitiesRequest(
                query = query,
                variables = WorkloadVulnerabilitiesRequest.Variables(
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
                logger.error("HTTP error fetching $workloadType vulnerabilities for user $email", e)
                throw e
            }

            val pageResponse: WorkloadVulnerabilitiesResponse = response.body()

            if (!pageResponse.errors.isNullOrEmpty()) {
                logger.error("GraphQL errors for user $workloadType vulnerabilities $email: ${pageResponse.errors.joinToString { "${it.message} at ${it.path}" }}")
                return pageResponse
            }

            if (pageResponse.data?.user == null) {
                return WorkloadVulnerabilitiesResponse(
                    errors = listOf(
                        WorkloadVulnerabilitiesResponse.GraphQLError(
                            message = "User not found or no data returned",
                            path = listOf("user")
                        )
                    )
                )
            }

            val teams = pageResponse.data.user.teams

            for (teamNode in teams.nodes) {
                val teamSlug = teamNode.team.slug
                val workloadConnection = when (workloadType) {
                    "applications" -> teamNode.team.applications
                    "jobs" -> teamNode.team.jobs
                    else -> null
                } ?: continue

                val allWorkloadsWithVulns = mutableListOf<WorkloadVulnerabilitiesResponse.WorkloadNode>()
                var workloadCursor = workloadConnection.pageInfo.endCursor
                var hasMoreWorkloads = workloadConnection.pageInfo.hasNextPage

                for (workload in workloadConnection.nodes) {
                    allWorkloadsWithVulns.add(paginateVulnerabilitiesForWorkload(workload, email, teamCursor, query, workloadType))
                }

                while (hasMoreWorkloads) {
                    val workloadRequest = WorkloadVulnerabilitiesRequest(
                        query = query,
                        variables = WorkloadVulnerabilitiesRequest.Variables(
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
                        logger.error("HTTP error fetching $workloadType for team $teamSlug", e)
                        throw e
                    }

                    val workloadPageResponse: WorkloadVulnerabilitiesResponse = workloadResponse.body()

                    if (!workloadPageResponse.errors.isNullOrEmpty()) {
                        logger.error("GraphQL errors fetching $workloadType for team $teamSlug: ${workloadPageResponse.errors.joinToString { "${it.message} at ${it.path}" }}")
                        break
                    }

                    val workloadTeamNode = workloadPageResponse.data?.user?.teams?.nodes?.firstOrNull()
                    if (workloadTeamNode != null) {
                        val newConnection = when (workloadType) {
                            "applications" -> workloadTeamNode.team.applications
                            "jobs" -> workloadTeamNode.team.jobs
                            else -> null
                        }
                        if (newConnection != null) {
                            for (workload in newConnection.nodes) {
                                allWorkloadsWithVulns.add(paginateVulnerabilitiesForWorkload(workload, email, teamCursor, query, workloadType))
                            }
                            hasMoreWorkloads = newConnection.pageInfo.hasNextPage
                            workloadCursor = newConnection.pageInfo.endCursor
                        } else {
                            break
                        }
                    } else {
                        break
                    }
                }

                val workloadsWithAllVulns = allWorkloadsWithVulns

                val teamWithWorkloads = when (workloadType) {
                    "applications" -> WorkloadVulnerabilitiesResponse.TeamNode(
                        team = WorkloadVulnerabilitiesResponse.Team(
                            slug = teamSlug,
                            applications = WorkloadVulnerabilitiesResponse.WorkloadConnection(
                                pageInfo = WorkloadVulnerabilitiesResponse.PageInfo(false, null),
                                nodes = workloadsWithAllVulns
                            ),
                            jobs = null
                        )
                    )
                    "jobs" -> WorkloadVulnerabilitiesResponse.TeamNode(
                        team = WorkloadVulnerabilitiesResponse.Team(
                            slug = teamSlug,
                            applications = null,
                            jobs = WorkloadVulnerabilitiesResponse.WorkloadConnection(
                                pageInfo = WorkloadVulnerabilitiesResponse.PageInfo(false, null),
                                nodes = workloadsWithAllVulns
                            )
                        )
                    )
                    else -> continue
                }

                allTeams.add(teamWithWorkloads)
            }

            hasMoreTeams = teams.pageInfo.hasNextPage
            teamCursor = teams.pageInfo.endCursor
        }

        return WorkloadVulnerabilitiesResponse(
            data = WorkloadVulnerabilitiesResponse.Data(
                user = WorkloadVulnerabilitiesResponse.User(
                    teams = WorkloadVulnerabilitiesResponse.Teams(
                        pageInfo = WorkloadVulnerabilitiesResponse.PageInfo(false, null),
                        nodes = allTeams
                    )
                )
            )
        )
    }

    private suspend fun paginateVulnerabilitiesForWorkload(
        workload: WorkloadVulnerabilitiesResponse.WorkloadNode,
        email: String,
        teamCursor: String?,
        query: String,
        workloadType: String
    ): WorkloadVulnerabilitiesResponse.WorkloadNode {
        if (workload.image == null) {
            return workload
        }

        val allVulns = mutableListOf<WorkloadVulnerabilitiesResponse.Vulnerability>()
        var vulnCursor: String?
        var hasMoreVulns: Boolean

        allVulns.addAll(workload.image.vulnerabilities.nodes)
        vulnCursor = workload.image.vulnerabilities.pageInfo.endCursor
        hasMoreVulns = workload.image.vulnerabilities.pageInfo.hasNextPage

        while (hasMoreVulns) {
            val vulnRequest = WorkloadVulnerabilitiesRequest(
                query = query,
                variables = WorkloadVulnerabilitiesRequest.Variables(
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

            val vulnPageResponse: WorkloadVulnerabilitiesResponse = vulnResponse.body()

            if (!vulnPageResponse.errors.isNullOrEmpty()) {
                logger.error("GraphQL errors fetching vulnerabilities for workload ${workload.id}: ${vulnPageResponse.errors.joinToString { "${it.message} at ${it.path}" }}")
                break
            }

            val paginatedWorkload = vulnPageResponse.data?.user?.teams?.nodes
                ?.firstOrNull()?.team?.let { team ->
                    when (workloadType) {
                        "applications" -> team.applications?.nodes
                        "jobs" -> team.jobs?.nodes
                        else -> null
                    }
                }
                ?.firstOrNull { it.id == workload.id }

            if (paginatedWorkload?.image != null) {
                allVulns.addAll(paginatedWorkload.image.vulnerabilities.nodes)
                hasMoreVulns = paginatedWorkload.image.vulnerabilities.pageInfo.hasNextPage
                vulnCursor = paginatedWorkload.image.vulnerabilities.pageInfo.endCursor
            } else {
                break
            }
        }

        return WorkloadVulnerabilitiesResponse.WorkloadNode(
            id = workload.id,
            name = workload.name,
            ingresses = workload.ingresses,
            deployments = workload.deployments,
            image = WorkloadVulnerabilitiesResponse.Image(
                name = workload.image.name,
                tag = workload.image.tag,
                vulnerabilities = WorkloadVulnerabilitiesResponse.Vulnerabilities(
                    pageInfo = WorkloadVulnerabilitiesResponse.PageInfo(false, null),
                    nodes = allVulns
                )
            )
        )
    }

    private fun mergeWorkloadResponses(
        appResponse: WorkloadVulnerabilitiesResponse,
        jobResponse: WorkloadVulnerabilitiesResponse
    ): List<WorkloadVulnerabilitiesResponse.TeamNode> {
        val appTeams = appResponse.data?.user?.teams?.nodes ?: emptyList()
        val jobTeams = jobResponse.data?.user?.teams?.nodes ?: emptyList()

        val allTeamSlugs = (appTeams.map { it.team.slug } + jobTeams.map { it.team.slug }).distinct()

        return allTeamSlugs.map { slug ->
            val appTeam = appTeams.firstOrNull { it.team.slug == slug }
            val jobTeam = jobTeams.firstOrNull { it.team.slug == slug }

            WorkloadVulnerabilitiesResponse.TeamNode(
                team = WorkloadVulnerabilitiesResponse.Team(
                    slug = slug,
                    applications = appTeam?.team?.applications,
                    jobs = jobTeam?.team?.jobs
                )
            )
        }
    }
}
