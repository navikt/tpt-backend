package no.nav.tpt.infrastructure.nais

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import no.nav.tpt.plugins.NaisApiException
import org.slf4j.LoggerFactory
import java.io.File
import java.io.IOException

class NaisApiClient(
    private val httpClient: HttpClient,
    private val apiUrl: String,
    private val tokenFilePath: String,
) : NaisApiService {
    private val logger = LoggerFactory.getLogger(NaisApiClient::class.java)
    private val paginationSemaphore = Semaphore(4)

    private data class PaginatedPage<T>(val items: List<T>, val hasNext: Boolean, val endCursor: String?)

    private fun readToken(): String =
        try {
            File(tokenFilePath).readText(Charsets.UTF_8)
        } catch (e: IOException) {
            logger.error("Failed to read NAIS service account token from $tokenFilePath", e)
            throw e
        }

    private suspend inline fun <reified Req, reified Res, Item> paginate(
        crossinline buildRequest: (cursor: String?) -> Req,
        crossinline extractPage: (Res) -> PaginatedPage<Item>?,
    ): List<Item> {
        val allItems = mutableListOf<Item>()
        var cursor: String? = null
        var hasNext = true

        while (hasNext) {
            val request = buildRequest(cursor)
            val httpResponse = try {
                httpClient.post(apiUrl) {
                    contentType(ContentType.Application.Json)
                    bearerAuth(readToken())
                    setBody(request)
                }
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                throw NaisApiException("HTTP transport error calling Nais API", e)
            }

            if (!httpResponse.status.isSuccess()) {
                throw NaisApiException("HTTP ${httpResponse.status.value}: ${httpResponse.status.description}")
            }

            val response: Res = httpResponse.body()
            val page = extractPage(response)
                ?: throw NaisApiException("No data returned from Nais API")

            allItems.addAll(page.items)
            hasNext = page.hasNext
            cursor = page.endCursor
        }

        return allItems
    }

    override suspend fun getAllTeams(): List<TeamInfo> {
        val nodes = paginate<TeamInformationRequest, TeamInformationResponse, TeamInformationResponse.TeamNode>(
            buildRequest = { cursor ->
                TeamInformationRequest(
                    query = TEAM_INFORMATION_QUERY,
                    variables = TeamInformationRequest.Variables(teamFirst = 200, teamAfter = cursor)
                )
            },
            extractPage = { response ->
                if (!response.errors.isNullOrEmpty()) {
                    throw NaisApiException(
                        "GraphQL errors fetching teams: ${response.errors.joinToString { "${it.message} at ${it.path}" }}"
                    )
                }
                val teams = response.data?.teams ?: return@paginate null
                PaginatedPage(
                    items = teams.nodes,
                    hasNext = teams.pageInfo.hasNextPage,
                    endCursor = teams.pageInfo.endCursor
                )
            }
        )
        return nodes.map { TeamInfo(it.slug, it.slackChannel) }
    }

    override suspend fun getVulnerabilitiesForUser(email: String): UserVulnerabilitiesData {
        val appTeamNodes = fetchUserWorkloads(email, APP_VULNERABILITIES_FOR_USER_QUERY, "applications")
        val jobTeamNodes = fetchUserWorkloads(email, JOB_VULNERABILITIES_FOR_USER_QUERY, "jobs")
        val mergedTeams = mergeUserTeamNodes(appTeamNodes, jobTeamNodes)
        return mapToUserVulnerabilitiesDataMultiTeam(mergedTeams)
    }

    override suspend fun getVulnerabilitiesForTeam(teamSlug: String): UserVulnerabilitiesData {
        val appWorkloads = fetchTeamWorkloads(teamSlug, APP_VULNERABILITIES_FOR_TEAM_QUERY, "applications")
        val jobWorkloads = fetchTeamWorkloads(teamSlug, JOB_VULNERABILITIES_FOR_TEAM_QUERY, "jobs")
        return mapToUserVulnerabilitiesData(teamSlug, appWorkloads, jobWorkloads)
    }

    private suspend fun fetchTeamWorkloads(
        teamSlug: String,
        query: String,
        workloadType: String,
    ): List<GraphQLTypes.WorkloadNode> {
        val workloads = paginate<TeamWorkloadVulnerabilitiesRequest, TeamWorkloadVulnerabilitiesResponse, GraphQLTypes.WorkloadNode>(
            buildRequest = { cursor ->
                TeamWorkloadVulnerabilitiesRequest(
                    query = query,
                    variables = TeamWorkloadVulnerabilitiesRequest.Variables(
                        team = teamSlug,
                        workloadFirst = 50,
                        workloadAfter = cursor,
                        vulnFirst = 50
                    )
                )
            },
            extractPage = { response ->
                if (!response.errors.isNullOrEmpty()) {
                    throw NaisApiException(
                        "GraphQL errors for team $teamSlug $workloadType: ${response.errors.joinToString { "${it.message} at ${it.path}" }}"
                    )
                }
                val team = response.data?.team
                    ?: throw NaisApiException("Team $teamSlug not found or no data returned")
                val connection = when (workloadType) {
                    "applications" -> team.applications
                    "jobs" -> team.jobs
                    else -> null
                } ?: return@paginate PaginatedPage(emptyList(), false, null)
                PaginatedPage(
                    items = connection.nodes,
                    hasNext = connection.pageInfo.hasNextPage,
                    endCursor = connection.pageInfo.endCursor
                )
            }
        )

        return coroutineScope {
            workloads.map { workload ->
                async {
                    paginationSemaphore.withPermit {
                        paginateVulnerabilities(
                            workload = workload,
                            buildVulnRequest = { vulnCursor ->
                                TeamWorkloadVulnerabilitiesRequest(
                                    query = query,
                                    variables = TeamWorkloadVulnerabilitiesRequest.Variables(
                                        team = teamSlug,
                                        workloadFirst = 50,
                                        workloadAfter = null,
                                        vulnFirst = 50,
                                        vulnAfter = vulnCursor
                                    )
                                )
                            },
                            extractWorkload = { response: TeamWorkloadVulnerabilitiesResponse ->
                                val team = response.data?.team ?: return@paginateVulnerabilities null
                                when (workloadType) {
                                    "applications" -> team.applications?.nodes
                                    "jobs" -> team.jobs?.nodes
                                    else -> null
                                }?.firstOrNull { it.id == workload.id }
                            }
                        )
                    }
                }
            }.awaitAll()
        }
    }

    private suspend fun fetchUserWorkloads(
        email: String,
        query: String,
        workloadType: String,
    ): List<WorkloadVulnerabilitiesResponse.TeamNode> {
        val teamNodes = paginate<WorkloadVulnerabilitiesRequest, WorkloadVulnerabilitiesResponse, WorkloadVulnerabilitiesResponse.TeamNode>(
            buildRequest = { cursor ->
                WorkloadVulnerabilitiesRequest(
                    query = query,
                    variables = WorkloadVulnerabilitiesRequest.Variables(
                        email = email,
                        teamFirst = 1,
                        teamAfter = cursor,
                        workloadFirst = 50,
                        workloadAfter = null,
                        vulnFirst = 50
                    )
                )
            },
            extractPage = { response ->
                if (!response.errors.isNullOrEmpty()) {
                    throw NaisApiException(
                        "GraphQL errors for user $email $workloadType: ${response.errors.joinToString { "${it.message} at ${it.path}" }}"
                    )
                }
                val teams = response.data?.user?.teams
                    ?: throw NaisApiException("User $email not found or no data returned")
                PaginatedPage(
                    items = teams.nodes,
                    hasNext = teams.pageInfo.hasNextPage,
                    endCursor = teams.pageInfo.endCursor
                )
            }
        )

        return coroutineScope {
            teamNodes.map { teamNode ->
                async {
                    val teamSlug = teamNode.team.slug
                    val connection = when (workloadType) {
                        "applications" -> teamNode.team.applications
                        "jobs" -> teamNode.team.jobs
                        else -> null
                    }

                    val allWorkloads = if (connection != null) {
                        val initialWorkloads = connection.nodes.map { workload ->
                            async {
                                paginationSemaphore.withPermit {
                                    paginateVulnerabilities(
                                        workload = workload,
                                        buildVulnRequest = { vulnCursor ->
                                            WorkloadVulnerabilitiesRequest(
                                                query = query,
                                                variables = WorkloadVulnerabilitiesRequest.Variables(
                                                    email = email,
                                                    teamFirst = 1,
                                                    teamAfter = null,
                                                    workloadFirst = 50,
                                                    workloadAfter = null,
                                                    vulnFirst = 50,
                                                    vulnAfter = vulnCursor
                                                )
                                            )
                                        },
                                        extractWorkload = { response: WorkloadVulnerabilitiesResponse ->
                                            response.data?.user?.teams?.nodes?.firstOrNull()
                                                ?.team
                                                ?.let { team ->
                                                    when (workloadType) {
                                                        "applications" -> team.applications?.nodes
                                                        "jobs" -> team.jobs?.nodes
                                                        else -> null
                                                    }
                                                }?.firstOrNull { it.id == workload.id }
                                        }
                                    )
                                }
                            }
                        }.awaitAll().toMutableList()

                        var workloadCursor = connection.pageInfo.endCursor
                        var hasMoreWorkloads = connection.pageInfo.hasNextPage

                        while (hasMoreWorkloads) {
                            val workloadResponse: WorkloadVulnerabilitiesResponse = try {
                                httpClient.post(apiUrl) {
                                    contentType(ContentType.Application.Json)
                                    bearerAuth(readToken())
                                    setBody(
                                        WorkloadVulnerabilitiesRequest(
                                            query = query,
                                            variables = WorkloadVulnerabilitiesRequest.Variables(
                                                email = email,
                                                teamFirst = 1,
                                                teamAfter = null,
                                                workloadFirst = 50,
                                                workloadAfter = workloadCursor,
                                                vulnFirst = 50
                                            )
                                        )
                                    )
                                }.body()
                            } catch (e: kotlinx.coroutines.CancellationException) {
                                throw e
                            } catch (e: Exception) {
                                throw NaisApiException("HTTP transport error fetching more $workloadType for team $teamSlug", e)
                            }

                            if (!workloadResponse.errors.isNullOrEmpty()) {
                                throw NaisApiException(
                                    "GraphQL errors fetching more $workloadType for team $teamSlug: ${workloadResponse.errors.joinToString { "${it.message} at ${it.path}" }}"
                                )
                            }

                            val newConnection = workloadResponse.data?.user?.teams?.nodes
                                ?.firstOrNull()
                                ?.team
                                ?.let { team ->
                                    when (workloadType) {
                                        "applications" -> team.applications
                                        "jobs" -> team.jobs
                                        else -> null
                                    }
                                } ?: break

                            initialWorkloads.addAll(
                                newConnection.nodes.map { workload ->
                                    async {
                                        paginationSemaphore.withPermit {
                                            paginateVulnerabilities(
                                                workload = workload,
                                                buildVulnRequest = { vulnCursor ->
                                                    WorkloadVulnerabilitiesRequest(
                                                        query = query,
                                                        variables = WorkloadVulnerabilitiesRequest.Variables(
                                                            email = email,
                                                            teamFirst = 1,
                                                            teamAfter = null,
                                                            workloadFirst = 50,
                                                            workloadAfter = null,
                                                            vulnFirst = 50,
                                                            vulnAfter = vulnCursor
                                                        )
                                                    )
                                                },
                                                extractWorkload = { response: WorkloadVulnerabilitiesResponse ->
                                                    response.data?.user?.teams?.nodes?.firstOrNull()
                                                        ?.team
                                                        ?.let { team ->
                                                            when (workloadType) {
                                                                "applications" -> team.applications?.nodes
                                                                "jobs" -> team.jobs?.nodes
                                                                else -> null
                                                            }
                                                        }?.firstOrNull { it.id == workload.id }
                                                }
                                            )
                                        }
                                    }
                                }.awaitAll()
                            )

                            hasMoreWorkloads = newConnection.pageInfo.hasNextPage
                            workloadCursor = newConnection.pageInfo.endCursor
                        }

                        initialWorkloads
                    } else {
                        emptyList()
                    }

                    WorkloadVulnerabilitiesResponse.TeamNode(
                        team = GraphQLTypes.Team(
                            slug = teamSlug,
                            applications = if (workloadType == "applications")
                                GraphQLTypes.WorkloadConnection(GraphQLTypes.PageInfo(false, null), allWorkloads)
                            else teamNode.team.applications,
                            jobs = if (workloadType == "jobs")
                                GraphQLTypes.WorkloadConnection(GraphQLTypes.PageInfo(false, null), allWorkloads)
                            else teamNode.team.jobs
                        )
                    )
                }
            }.awaitAll()
        }
    }

    private suspend inline fun <reified Req, reified Res> paginateVulnerabilities(
        workload: GraphQLTypes.WorkloadNode,
        crossinline buildVulnRequest: (cursor: String?) -> Req,
        crossinline extractWorkload: (Res) -> GraphQLTypes.WorkloadNode?,
    ): GraphQLTypes.WorkloadNode {
        if (workload.image == null) return workload

        val allVulns = workload.image.vulnerabilities.nodes.toMutableList()
        var vulnCursor = workload.image.vulnerabilities.pageInfo.endCursor
        var hasMoreVulns = workload.image.vulnerabilities.pageInfo.hasNextPage

        while (hasMoreVulns) {
            val response: Res = try {
                httpClient.post(apiUrl) {
                    contentType(ContentType.Application.Json)
                    bearerAuth(readToken())
                    setBody(buildVulnRequest(vulnCursor))
                }.body()
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                logger.error("HTTP error fetching vulnerabilities for workload ${workload.id}", e)
                break
            }

            val paginatedWorkload = extractWorkload(response)
            if (paginatedWorkload?.image != null) {
                allVulns.addAll(paginatedWorkload.image.vulnerabilities.nodes)
                hasMoreVulns = paginatedWorkload.image.vulnerabilities.pageInfo.hasNextPage
                vulnCursor = paginatedWorkload.image.vulnerabilities.pageInfo.endCursor
            } else {
                break
            }
        }

        return GraphQLTypes.WorkloadNode(
            id = workload.id,
            name = workload.name,
            ingresses = workload.ingresses,
            deployments = workload.deployments,
            image = GraphQLTypes.Image(
                name = workload.image.name,
                tag = workload.image.tag,
                vulnerabilities = GraphQLTypes.Vulnerabilities(
                    pageInfo = GraphQLTypes.PageInfo(false, null),
                    nodes = allVulns
                )
            )
        )
    }

    private fun mergeUserTeamNodes(
        appTeamNodes: List<WorkloadVulnerabilitiesResponse.TeamNode>,
        jobTeamNodes: List<WorkloadVulnerabilitiesResponse.TeamNode>,
    ): List<WorkloadVulnerabilitiesResponse.TeamNode> {
        val allSlugs = (appTeamNodes.map { it.team.slug } + jobTeamNodes.map { it.team.slug }).distinct()
        return allSlugs.map { slug ->
            val appNode = appTeamNodes.firstOrNull { it.team.slug == slug }
            val jobNode = jobTeamNodes.firstOrNull { it.team.slug == slug }
            WorkloadVulnerabilitiesResponse.TeamNode(
                team = GraphQLTypes.Team(
                    slug = slug,
                    applications = appNode?.team?.applications,
                    jobs = jobNode?.team?.jobs
                )
            )
        }
    }

    override suspend fun getTeamMembershipsForUser(email: String): List<String> {
        val response = getTeamMembershipsRaw(email)

        if (!response.errors.isNullOrEmpty()) {
            logger.warn("GraphQL errors for team memberships $email: ${response.errors.joinToString { "${it.message} at ${it.path}" }}")
            return emptyList()
        }

        return response.data
            ?.user
            ?.teams
            ?.nodes
            ?.map { it.team.slug } ?: emptyList()
    }

    private suspend fun getTeamMembershipsRaw(email: String): TeamMembershipsForUserResponse {
        val request = TeamMembershipsForUserRequest(
            query = TEAM_MEMBERSHIPS_FOR_USER_QUERY,
            variables = TeamMembershipsForUserRequest.Variables(email = email)
        )

        return try {
            val response = httpClient.post(apiUrl) {
                contentType(ContentType.Application.Json)
                bearerAuth(readToken())
                setBody(request)
            }

            if (!response.status.isSuccess()) {
                logger.error("Failed to fetch team memberships for user $email: ${response.status}")
                return TeamMembershipsForUserResponse(
                    errors = listOf(
                        TeamMembershipsForUserResponse.GraphQLError(
                            message = "HTTP ${response.status.value}: ${response.status.description}",
                            path = listOf("user", "teams")
                        )
                    )
                )
            }

            response.body<TeamMembershipsForUserResponse>()
        } catch (e: Exception) {
            logger.error("Error fetching team memberships for user $email", e)
            TeamMembershipsForUserResponse(
                errors = listOf(
                    TeamMembershipsForUserResponse.GraphQLError(
                        message = "Failed to fetch team memberships: ${e.message}",
                        path = listOf("user", "teams")
                    )
                )
            )
        }
    }
}
