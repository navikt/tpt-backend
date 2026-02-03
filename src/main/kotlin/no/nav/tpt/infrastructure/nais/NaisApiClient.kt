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
) : NaisApiService {
    private val logger = LoggerFactory.getLogger(NaisApiClient::class.java)

    private val applicationsForUserQuery = this::class.java.classLoader
        .getResource("graphql/app-vulnerabilities-for-user.graphql")
        ?.readText()
        ?: error("Could not load app-vulnerabilities-for-user.graphql")

    private val jobVulnerabilitiesForUserQuery = this::class.java.classLoader
        .getResource("graphql/job-vulnerabilities-for-user.graphql")
        ?.readText()
        ?: error("Could not load job-vulnerabilities-for-user.graphql")

    private val applicationsForTeamQuery = this::class.java.classLoader
        .getResource("graphql/app-vulnerabilities-for-team.graphql")
        ?.readText()
        ?: error("Could not load app-vulnerabilities-for-team.graphql")

    private val jobVulnerabilitiesForTeamQuery = this::class.java.classLoader
        .getResource("graphql/job-vulnerabilities-for-team.graphql")
        ?.readText()
        ?: error("Could not load job-vulnerabilities-for-team.graphql")

    private val teamMembershipsForUserQuery = this::class.java.classLoader
        .getResource("graphql/team-memberships-for-user.graphql")
        ?.readText()
        ?: error("Could not load team-memberships-for-user.graphql")

    private val teamInformationQuery = this::class.java.classLoader
        .getResource("graphql/team-information.graphql")
        ?.readText()
        ?: error("Could not load team-information.graphql")

    override suspend fun getAllTeams(): List<TeamInfo> {
        val allTeams = mutableListOf<TeamInformationResponse.TeamNode>()
        var cursor: String? = null
        var hasNextPage = true

        while (hasNextPage) {
            val request = TeamInformationRequest(
                query = teamInformationQuery,
                variables = TeamInformationRequest.Variables(
                    teamFirst = 200,
                    teamAfter = cursor
                )
            )

            val response = try {
                httpClient.post(apiUrl) {
                    contentType(ContentType.Application.Json)
                    bearerAuth(token)
                    setBody(request)
                }
            } catch (e: Exception) {
                logger.error("HTTP error fetching teams", e)
                throw e
            }

            val pageResponse: TeamInformationResponse = response.body()

            if (!pageResponse.errors.isNullOrEmpty()) {
                logger.error("GraphQL errors fetching teams: ${pageResponse.errors.joinToString { "${it.message} at ${it.path}" }}")
                throw Exception("Failed to fetch teams: ${pageResponse.errors.first().message}")
            }

            if (pageResponse.data?.teams == null) {
                throw Exception("No data returned when fetching teams")
            }

            allTeams.addAll(pageResponse.data.teams.nodes)
            hasNextPage = pageResponse.data.teams.pageInfo.hasNextPage
            cursor = pageResponse.data.teams.pageInfo.endCursor
        }

        return allTeams.map { TeamInfo(it.slug, it.slackChannel) }
    }

    override suspend fun getVulnerabilitiesForUser(email: String): UserVulnerabilitiesData {
        val appResponse = fetchWorkloadVulnerabilities(email, applicationsForUserQuery, "applications")
        val jobResponse = fetchWorkloadVulnerabilities(email, jobVulnerabilitiesForUserQuery, "jobs")

        if (!appResponse.errors.isNullOrEmpty() || !jobResponse.errors.isNullOrEmpty()) {
            val allErrors = (appResponse.errors ?: emptyList()) + (jobResponse.errors ?: emptyList())
            return WorkloadVulnerabilitiesResponse(errors = allErrors).toData()
        }

        val mergedTeams = mergeWorkloadResponses(appResponse, jobResponse)

        return WorkloadVulnerabilitiesResponse(
            data = WorkloadVulnerabilitiesResponse.Data(
                user = WorkloadVulnerabilitiesResponse.User(
                    teams = WorkloadVulnerabilitiesResponse.Teams(
                        pageInfo = GraphQLTypes.PageInfo(false, null),
                        nodes = mergedTeams
                    )
                )
            )
        ).toData()
    }

    override suspend fun getVulnerabilitiesForTeam(teamSlug: String): UserVulnerabilitiesData {
        val appResponse = fetchTeamWorkloadVulnerabilities(teamSlug, applicationsForTeamQuery, "applications")
        val jobResponse = fetchTeamWorkloadVulnerabilities(teamSlug, jobVulnerabilitiesForTeamQuery, "jobs")

        if (!appResponse.errors.isNullOrEmpty() || !jobResponse.errors.isNullOrEmpty()) {
            val allErrors = (appResponse.errors ?: emptyList()) + (jobResponse.errors ?: emptyList())
            val errorMessage = allErrors.joinToString("; ") { "${it.message} at ${it.path}" }
            throw Exception("GraphQL errors for team $teamSlug: $errorMessage")
        }

        val appTeam = appResponse.data?.team
        val jobTeam = jobResponse.data?.team

        if (appTeam == null && jobTeam == null) {
            throw Exception("Team $teamSlug not found or no data returned")
        }

        val team = WorkloadVulnerabilitiesResponse.TeamNode(
            team = GraphQLTypes.Team(
                slug = teamSlug,
                applications = appTeam?.applications?.let { apps ->
                    GraphQLTypes.WorkloadConnection(
                        pageInfo = GraphQLTypes.PageInfo(apps.pageInfo.hasNextPage, apps.pageInfo.endCursor),
                        nodes = apps.nodes.map { convertTeamWorkloadToUserWorkload(it) }
                    )
                },
                jobs = jobTeam?.jobs?.let { jobs ->
                    GraphQLTypes.WorkloadConnection(
                        pageInfo = GraphQLTypes.PageInfo(jobs.pageInfo.hasNextPage, jobs.pageInfo.endCursor),
                        nodes = jobs.nodes.map { convertTeamWorkloadToUserWorkload(it) }
                    )
                }
            )
        )

        return WorkloadVulnerabilitiesResponse(
            data = WorkloadVulnerabilitiesResponse.Data(
                user = WorkloadVulnerabilitiesResponse.User(
                    teams = WorkloadVulnerabilitiesResponse.Teams(
                        pageInfo = GraphQLTypes.PageInfo(false, null),
                        nodes = listOf(team)
                    )
                )
            )
        ).toData()
    }

    private fun convertTeamWorkloadToUserWorkload(
        teamWorkload: GraphQLTypes.WorkloadNode
    ): GraphQLTypes.WorkloadNode {
        return teamWorkload
    }

    private suspend fun fetchTeamWorkloadVulnerabilities(
        teamSlug: String,
        query: String,
        workloadType: String
    ): TeamWorkloadVulnerabilitiesResponse {
        val allWorkloadsWithVulns = mutableListOf<GraphQLTypes.WorkloadNode>()
        var workloadCursor: String? = null
        var hasMoreWorkloads = true

        while (hasMoreWorkloads) {
            val request = TeamWorkloadVulnerabilitiesRequest(
                query = query,
                variables = TeamWorkloadVulnerabilitiesRequest.Variables(
                    team = teamSlug,
                    workloadFirst = 50,
                    workloadAfter = workloadCursor,
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
                logger.error("HTTP error fetching $workloadType for team $teamSlug", e)
                throw e
            }

            val pageResponse: TeamWorkloadVulnerabilitiesResponse = response.body()

            if (!pageResponse.errors.isNullOrEmpty()) {
                logger.error("GraphQL errors for team $workloadType $teamSlug: ${pageResponse.errors.joinToString { "${it.message} at ${it.path}" }}")
                return pageResponse
            }

            if (pageResponse.data?.team == null) {
                return TeamWorkloadVulnerabilitiesResponse(
                    errors = listOf(
                        GraphQLTypes.GraphQLError(
                            message = "Team not found or no data returned",
                            path = listOf("team")
                        )
                    )
                )
            }

            val workloadConnection = when (workloadType) {
                "applications" -> pageResponse.data.team.applications
                "jobs" -> pageResponse.data.team.jobs
                else -> null
            }

            if (workloadConnection == null) {
                break
            }

            for (workload in workloadConnection.nodes) {
                allWorkloadsWithVulns.add(paginateVulnerabilitiesForTeamWorkload(workload, teamSlug, query, workloadType))
            }

            hasMoreWorkloads = workloadConnection.pageInfo.hasNextPage
            workloadCursor = workloadConnection.pageInfo.endCursor
        }

        val slug = allWorkloadsWithVulns.firstOrNull()?.let { teamSlug } ?: teamSlug

        return TeamWorkloadVulnerabilitiesResponse(
            data = TeamWorkloadVulnerabilitiesResponse.Data(
                team = GraphQLTypes.Team(
                    slug = slug,
                    applications = if (workloadType == "applications")
                        GraphQLTypes.WorkloadConnection(
                            pageInfo = GraphQLTypes.PageInfo(false, null),
                            nodes = allWorkloadsWithVulns
                        ) else null,
                    jobs = if (workloadType == "jobs")
                        GraphQLTypes.WorkloadConnection(
                            pageInfo = GraphQLTypes.PageInfo(false, null),
                            nodes = allWorkloadsWithVulns
                        ) else null
                )
            )
        )
    }

    private suspend fun paginateVulnerabilitiesForTeamWorkload(
        workload: GraphQLTypes.WorkloadNode,
        teamSlug: String,
        query: String,
        workloadType: String
    ): GraphQLTypes.WorkloadNode {
        if (workload.image == null) {
            return workload
        }

        val allVulns = mutableListOf<GraphQLTypes.Vulnerability>()
        var vulnCursor: String?
        var hasMoreVulns: Boolean

        allVulns.addAll(workload.image.vulnerabilities.nodes)
        vulnCursor = workload.image.vulnerabilities.pageInfo.endCursor
        hasMoreVulns = workload.image.vulnerabilities.pageInfo.hasNextPage

        while (hasMoreVulns) {
            val vulnRequest = TeamWorkloadVulnerabilitiesRequest(
                query = query,
                variables = TeamWorkloadVulnerabilitiesRequest.Variables(
                    team = teamSlug,
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

            val vulnPageResponse: TeamWorkloadVulnerabilitiesResponse = vulnResponse.body()

            if (!vulnPageResponse.errors.isNullOrEmpty()) {
                logger.error("GraphQL errors fetching vulnerabilities for workload ${workload.id}: ${vulnPageResponse.errors.joinToString { "${it.message} at ${it.path}" }}")
                break
            }

            val paginatedWorkload = vulnPageResponse.data?.team?.let { team ->
                when (workloadType) {
                    "applications" -> team.applications?.nodes
                    "jobs" -> team.jobs?.nodes
                    else -> null
                }
            }?.firstOrNull { it.id == workload.id }

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
                        GraphQLTypes.GraphQLError(
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

                val allWorkloadsWithVulns = mutableListOf<GraphQLTypes.WorkloadNode>()
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
                        team = GraphQLTypes.Team(
                            slug = teamSlug,
                            applications = GraphQLTypes.WorkloadConnection(
                                pageInfo = GraphQLTypes.PageInfo(false, null),
                                nodes = workloadsWithAllVulns
                            ),
                            jobs = null
                        )
                    )
                    "jobs" -> WorkloadVulnerabilitiesResponse.TeamNode(
                        team = GraphQLTypes.Team(
                            slug = teamSlug,
                            applications = null,
                            jobs = GraphQLTypes.WorkloadConnection(
                                pageInfo = GraphQLTypes.PageInfo(false, null),
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
                        pageInfo = GraphQLTypes.PageInfo(false, null),
                        nodes = allTeams
                    )
                )
            )
        )
    }

    private suspend fun paginateVulnerabilitiesForWorkload(
        workload: GraphQLTypes.WorkloadNode,
        email: String,
        teamCursor: String?,
        query: String,
        workloadType: String
    ): GraphQLTypes.WorkloadNode {
        if (workload.image == null) {
            return workload
        }

        val allVulns = mutableListOf<GraphQLTypes.Vulnerability>()
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
                team = GraphQLTypes.Team(
                    slug = slug,
                    applications = appTeam?.team?.applications,
                    jobs = jobTeam?.team?.jobs
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

        return response.data?.user?.teams?.nodes?.map { it.team.slug } ?: emptyList()
    }

    private suspend fun getTeamMembershipsRaw(email: String): TeamMembershipsForUserResponse {
        val request = TeamMembershipsForUserRequest(
            query = teamMembershipsForUserQuery,
            variables = TeamMembershipsForUserRequest.Variables(email = email)
        )

        return try {
            val response = httpClient.post("$apiUrl") {
                contentType(ContentType.Application.Json)
                bearerAuth(token)
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
