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

    suspend fun getApplicationsForUser(email: String): ApplicationsForUserResponse {
        val allTeamNodes = mutableListOf<ApplicationsForUserResponse.TeamNode>()
        var teamCursor: String? = null
        var hasMoreTeams = true

        // Level 2: Paginate teams (10 at a time)
        while (hasMoreTeams) {
            val request = ApplicationsForUserRequest(
                query = applicationsForUserQuery,
                variables = ApplicationsForUserRequest.Variables(
                    email = email,
                    appFirst = 100,
                    appAfter = null,
                    teamsFirst = 10,
                    teamsAfter = teamCursor
                )
            )

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

            if (!pageResponse.errors.isNullOrEmpty()) {
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

            // Process each team
            for (teamNode in teams.nodes) {
                val allApps = mutableListOf<ApplicationsForUserResponse.Application>()
                var appCursor = teamNode.team.applications.pageInfo.endCursor
                var hasMoreApps = teamNode.team.applications.pageInfo.hasNextPage

                // Add initial applications from first team request
                allApps.addAll(teamNode.team.applications.nodes)

                // Level 1: Paginate applications (100 at a time) for each team
                while (hasMoreApps) {
                    val appRequest = ApplicationsForUserRequest(
                        query = applicationsForUserQuery,
                        variables = ApplicationsForUserRequest.Variables(
                            email = email,
                            appFirst = 100,
                            appAfter = appCursor,
                            teamsFirst = 10,
                            teamsAfter = teamCursor
                        )
                    )

                    val appResponse = try {
                        httpClient.post(apiUrl) {
                            contentType(ContentType.Application.Json)
                            bearerAuth(token)
                            setBody(appRequest)
                        }
                    } catch (e: Exception) {
                        logger.error("HTTP error fetching applications for team ${teamNode.team.slug}", e)
                        throw e
                    }

                    val appPageResponse: ApplicationsForUserResponse = appResponse.body()

                    if (!appPageResponse.errors.isNullOrEmpty()) {
                        logger.error("GraphQL errors fetching applications for team ${teamNode.team.slug}: ${appPageResponse.errors.joinToString { "${it.message} at ${it.path}" }}")
                        break
                    }

                    val appTeamNode = appPageResponse.data?.user?.teams?.nodes?.firstOrNull { it.team.slug == teamNode.team.slug }
                    if (appTeamNode != null) {
                        allApps.addAll(appTeamNode.team.applications.nodes)
                        hasMoreApps = appTeamNode.team.applications.pageInfo.hasNextPage
                        appCursor = appTeamNode.team.applications.pageInfo.endCursor
                    } else {
                        break
                    }
                }

                allTeamNodes.add(
                    ApplicationsForUserResponse.TeamNode(
                        team = ApplicationsForUserResponse.Team(
                            slug = teamNode.team.slug,
                            applications = ApplicationsForUserResponse.Applications(
                                pageInfo = ApplicationsForUserResponse.PageInfo(false, null),
                                nodes = allApps
                            )
                        )
                    )
                )
            }

            hasMoreTeams = teams.pageInfo.hasNextPage
            teamCursor = teams.pageInfo.endCursor
        }

        return ApplicationsForUserResponse(
            data = ApplicationsForUserResponse.Data(
                user = ApplicationsForUserResponse.User(
                    teams = ApplicationsForUserResponse.Teams(
                        pageInfo = ApplicationsForUserResponse.PageInfo(false, null),
                        nodes = allTeamNodes
                    )
                )
            )
        )
    }

    suspend fun getVulnerabilitiesForUser(email: String): VulnerabilitiesForUserResponse {
        val allTeams = mutableListOf<VulnerabilitiesForUserResponse.TeamNode>()
        var teamCursor: String? = null
        var hasMoreTeams = true

        // Level 3: Paginate teams (1 at a time)
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
                var workloadCursor = teamNode.team.workloads.pageInfo.endCursor
                var hasMoreWorkloads = teamNode.team.workloads.pageInfo.hasNextPage

                // Add initial workloads from first team request
                allWorkloads.addAll(teamNode.team.workloads.nodes)

                // Level 2: Paginate workloads (50 at a time)
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
                        allWorkloads.addAll(workloadTeamNode.team.workloads.nodes)
                        hasMoreWorkloads = workloadTeamNode.team.workloads.pageInfo.hasNextPage
                        workloadCursor = workloadTeamNode.team.workloads.pageInfo.endCursor
                    } else {
                        break
                    }
                }

                // Level 1: Paginate vulnerabilities (50 at a time) for each workload
                // Deduplicate workloads by ID and merge their vulnerabilities
                val uniqueWorkloads = allWorkloads.groupBy { it.id }.map { (_, workloads) ->
                    val firstWorkload = workloads.first()
                    // Merge all vulnerabilities from all occurrences of this workload
                    val allVulns = workloads.flatMap { it.image?.vulnerabilities?.nodes ?: emptyList() }
                    // Use the last occurrence's pageInfo to determine if there are more vulns to fetch
                    val lastWorkload = workloads.last()
                    val shouldPaginateMore = lastWorkload.image?.vulnerabilities?.pageInfo?.hasNextPage ?: false

                    VulnerabilitiesForUserResponse.WorkloadNode(
                        id = firstWorkload.id,
                        name = firstWorkload.name,
                        deployments = firstWorkload.deployments,
                        image = firstWorkload.image?.let { img ->
                            VulnerabilitiesForUserResponse.Image(
                                name = img.name,
                                tag = img.tag,
                                vulnerabilities = VulnerabilitiesForUserResponse.Vulnerabilities(
                                    pageInfo = VulnerabilitiesForUserResponse.PageInfo(
                                        hasNextPage = shouldPaginateMore,
                                        endCursor = lastWorkload.image?.vulnerabilities?.pageInfo?.endCursor
                                    ),
                                    nodes = allVulns
                                )
                            )
                        }
                    )
                }

                val workloadsWithAllVulns = uniqueWorkloads.map { workload ->
                    if (workload.image == null) {
                        workload
                    } else {
                        val allVulns = mutableListOf<VulnerabilitiesForUserResponse.Vulnerability>()
                        var vulnCursor: String?
                        var hasMoreVulns: Boolean

                        allVulns.addAll(workload.image.vulnerabilities.nodes)
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
                                allVulns.addAll(paginatedWorkload.image.vulnerabilities.nodes)
                                hasMoreVulns = paginatedWorkload.image.vulnerabilities.pageInfo.hasNextPage
                                vulnCursor = paginatedWorkload.image.vulnerabilities.pageInfo.endCursor
                            } else {
                                break
                            }
                        }

                        VulnerabilitiesForUserResponse.WorkloadNode(
                            id = workload.id,
                            name = workload.name,
                            deployments = workload.deployments,
                            image = VulnerabilitiesForUserResponse.Image(
                                name = workload.image.name,
                                tag = workload.image.tag,
                                vulnerabilities = VulnerabilitiesForUserResponse.Vulnerabilities(
                                    pageInfo = VulnerabilitiesForUserResponse.PageInfo(false, null),
                                    nodes = allVulns
                                )
                            )
                        )
                    }
                }

                allTeams.add(
                    VulnerabilitiesForUserResponse.TeamNode(
                        team = VulnerabilitiesForUserResponse.Team(
                            slug = teamSlug,
                            workloads = VulnerabilitiesForUserResponse.Workloads(
                                pageInfo = VulnerabilitiesForUserResponse.PageInfo(false, null),
                                nodes = workloadsWithAllVulns
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
                        pageInfo = VulnerabilitiesForUserResponse.PageInfo(false, null),
                        nodes = allTeams
                    )
                )
            )
        )
    }
}
