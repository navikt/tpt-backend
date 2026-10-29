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
                val httpResponse = httpClient.post(apiUrl) {
                    contentType(ContentType.Application.Json)
                    bearerAuth(readToken())
                    setBody(buildVulnRequest(vulnCursor))
                }
                if (!httpResponse.status.isSuccess()) {
                    logger.error("HTTP ${httpResponse.status.value} fetching vulnerabilities for workload ${workload.id}")
                    break
                }
                httpResponse.body()
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
