package no.nav.tpt.infrastructure.user

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.json
import io.ktor.utils.io.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import no.nav.tpt.domain.user.UserRole
import no.nav.tpt.infrastructure.nais.*
import no.nav.tpt.infrastructure.teamkatalogen.TeamkatalogenApiResponse
import no.nav.tpt.infrastructure.teamkatalogen.TeamMembership
import no.nav.tpt.infrastructure.teamkatalogen.TeamkatalogenClient
import no.nav.tpt.infrastructure.teamkatalogen.TeamkatalogenServiceImpl
import kotlin.test.Test
import kotlin.test.assertEquals

class UserContextServiceImplTest {

    @Test
    fun `should create user context with teams from nais api when available`() = runTest {
        val mockHttpClient = HttpClient(MockEngine) {
            engine {
                addHandler { request ->
                    when (request.url.encodedPath) {
                        "/query" -> respond(
                            content = ByteReadChannel("""{"data":{"teams":[]}}"""),
                            status = HttpStatusCode.OK,
                            headers = headersOf(HttpHeaders.ContentType, "application/json")
                        )
                        else -> error("Unhandled ${request.url.encodedPath}")
                    }
                }
            }
        }

        val naisApiService = object : NaisApiService {
            override suspend fun getAllTeams(): List<TeamInfo> = emptyList()
            override suspend fun getVulnerabilitiesForUser(email: String): UserVulnerabilitiesData {
                return UserVulnerabilitiesData(
                    teams = listOf(
                        TeamVulnerabilitiesData(
                            teamSlug = "team-a",
                            workloads = emptyList()
                        )
                    )
                )
            }

            override suspend fun getVulnerabilitiesForTeam(teamSlug: String): UserVulnerabilitiesData {
                return UserVulnerabilitiesData(
                    teams = listOf(
                        TeamVulnerabilitiesData(
                            teamSlug = teamSlug,
                            workloads = emptyList()
                        )
                    )
                )
            }

            override suspend fun getTeamMembershipsForUser(email: String): List<String> {
                return listOf("team-a")
            }
        }

        val teamkatalogenClient = TeamkatalogenClient(mockHttpClient, "https://teamkatalogen.nav.no")
        val teamkatalogenService = TeamkatalogenServiceImpl(teamkatalogenClient)

        val adminAuthorizationService = AdminAuthorizationServiceImpl("admin-group-1,admin-group-2")
        val userContextService = UserContextServiceImpl(naisApiService, teamkatalogenService, adminAuthorizationService)

        val userContext = userContextService.getUserContext("test@nav.no")

        assertEquals("test@nav.no", userContext.email)
        assertEquals(UserRole.DEVELOPER, userContext.role)
        assertEquals(listOf("team-a"), userContext.teams)
    }

    @Test
    fun `should fallback to teamkatalogen when nais api returns no teams`() = runTest {
        val mockHttpClient = HttpClient(MockEngine) {
            engine {
                addHandler { request ->
                    when (request.url.encodedPath) {
                        "/query" -> respond(
                            content = ByteReadChannel("""{"data":{"teams":[]}}"""),
                            status = HttpStatusCode.OK,
                            headers = headersOf(HttpHeaders.ContentType, "application/json")
                        )
                        "/member/membership/byUserEmail" -> {
                            val responseData = TeamkatalogenApiResponse(
                                teams = listOf(
                                    TeamMembership(naisTeams = listOf("team-b", "team-c"))
                                )
                            )
                            val json = Json {
                                prettyPrint = true
                                isLenient = true
                                ignoreUnknownKeys = true
                            }
                            respond(
                                content = ByteReadChannel(json.encodeToString(TeamkatalogenApiResponse.serializer(), responseData)),
                                status = HttpStatusCode.OK,
                                headers = headersOf(HttpHeaders.ContentType, "application/json")
                            )
                        }
                        else -> error("Unhandled ${request.url.encodedPath}")
                    }
                }
            }
            install(io.ktor.client.plugins.contentnegotiation.ContentNegotiation) {
                json(Json {
                    prettyPrint = true
                    isLenient = true
                    ignoreUnknownKeys = true
                })
            }
        }

        val naisApiService = object : NaisApiService {
            override suspend fun getAllTeams(): List<TeamInfo> = emptyList()
            override suspend fun getVulnerabilitiesForUser(email: String): UserVulnerabilitiesData {
                return UserVulnerabilitiesData(teams = emptyList())
            }

            override suspend fun getVulnerabilitiesForTeam(teamSlug: String): UserVulnerabilitiesData {
                return UserVulnerabilitiesData(
                    teams = listOf(
                        TeamVulnerabilitiesData(
                            teamSlug = teamSlug,
                            workloads = emptyList()
                        )
                    )
                )
            }

            override suspend fun getTeamMembershipsForUser(email: String): List<String> {
                return emptyList()
            }
        }

        val teamkatalogenClient = TeamkatalogenClient(mockHttpClient, "https://teamkatalogen.nav.no")
        val teamkatalogenService = TeamkatalogenServiceImpl(teamkatalogenClient)

        val adminAuthorizationService = AdminAuthorizationServiceImpl("admin-group-1,admin-group-2")
        val userContextService = UserContextServiceImpl(naisApiService, teamkatalogenService, adminAuthorizationService)

        val userContext = userContextService.getUserContext("test@nav.no")

        assertEquals("test@nav.no", userContext.email)
        assertEquals(UserRole.TEAM_MEMBER, userContext.role)
        assertEquals(listOf("team-b", "team-c"), userContext.teams)
    }

    @Test
    fun `should assign DEVELOPER role when user has nais team memberships`() = runTest {
        val mockHttpClient = HttpClient(MockEngine) {
            engine {
                addHandler { request ->
                    when (request.url.encodedPath) {
                        "/" -> respond(
                            content = ByteReadChannel("""{"data":{"teams":[]}}"""),
                            status = HttpStatusCode.OK,
                            headers = headersOf(HttpHeaders.ContentType, "application/json")
                        )
                        else -> error("Unhandled ${request.url.encodedPath}")
                    }
                }
            }
        }

        val naisApiService = object : NaisApiService {
            override suspend fun getAllTeams(): List<TeamInfo> = emptyList()
            override suspend fun getVulnerabilitiesForUser(email: String): UserVulnerabilitiesData {
                return UserVulnerabilitiesData(
                    teams = listOf(
                        TeamVulnerabilitiesData(
                            teamSlug = "team-a",
                            workloads = emptyList()
                        )
                    )
                )
            }

            override suspend fun getVulnerabilitiesForTeam(teamSlug: String): UserVulnerabilitiesData {
                return UserVulnerabilitiesData(
                    teams = listOf(
                        TeamVulnerabilitiesData(
                            teamSlug = teamSlug,
                            workloads = emptyList()
                        )
                    )
                )
            }

            override suspend fun getTeamMembershipsForUser(email: String): List<String> {
                return listOf("team-a")
            }
        }

        val teamkatalogenClient = TeamkatalogenClient(mockHttpClient, "https://teamkatalogen.nav.no")
        val teamkatalogenService = TeamkatalogenServiceImpl(teamkatalogenClient)

        val adminAuthorizationService = AdminAuthorizationServiceImpl("admin-group-1,admin-group-2")
        val userContextService = UserContextServiceImpl(naisApiService, teamkatalogenService, adminAuthorizationService)

        val userContext = userContextService.getUserContext("member@nav.no")

        assertEquals("member@nav.no", userContext.email)
        assertEquals(UserRole.DEVELOPER, userContext.role)
        assertEquals(listOf("team-a"), userContext.teams)
    }

    @Test
    fun `should handle user not found and assign NONE role when no teams found`() = runTest {
        val mockHttpClient = HttpClient(MockEngine) {
            engine {
                addHandler { request ->
                    when (request.url.encodedPath) {
                        "/" -> respond(
                            content = ByteReadChannel("""{"data":{"teams":[]}}"""),
                            status = HttpStatusCode.OK,
                            headers = headersOf(HttpHeaders.ContentType, "application/json")
                        )
                        "/member/membership/byUserEmail" -> {
                            val responseData = TeamkatalogenApiResponse(
                                teams = emptyList()
                            )
                            val json = Json {
                                prettyPrint = true
                                isLenient = true
                                ignoreUnknownKeys = true
                            }
                            respond(
                                content = ByteReadChannel(json.encodeToString(TeamkatalogenApiResponse.serializer(), responseData)),
                                status = HttpStatusCode.OK,
                                headers = headersOf(HttpHeaders.ContentType, "application/json")
                            )
                        }
                        else -> error("Unhandled ${request.url.encodedPath}")
                    }
                }
            }
            install(io.ktor.client.plugins.contentnegotiation.ContentNegotiation) {
                json(Json {
                    prettyPrint = true
                    isLenient = true
                    ignoreUnknownKeys = true
                })
            }
        }

        val naisApiService = object : NaisApiService {
            override suspend fun getAllTeams(): List<TeamInfo> = emptyList()
            override suspend fun getVulnerabilitiesForUser(email: String): UserVulnerabilitiesData {
                return UserVulnerabilitiesData(teams = emptyList())
            }

            override suspend fun getVulnerabilitiesForTeam(teamSlug: String): UserVulnerabilitiesData {
                return UserVulnerabilitiesData(
                    teams = listOf(
                        TeamVulnerabilitiesData(
                            teamSlug = teamSlug,
                            workloads = emptyList()
                        )
                    )
                )
            }

            override suspend fun getTeamMembershipsForUser(email: String): List<String> {
                return emptyList()
            }
        }

        val teamkatalogenClient = TeamkatalogenClient(mockHttpClient, "https://teamkatalogen.nav.no")
        val teamkatalogenService = TeamkatalogenServiceImpl(teamkatalogenClient)

        val adminAuthorizationService = AdminAuthorizationServiceImpl("admin-group-1,admin-group-2")
        val userContextService = UserContextServiceImpl(naisApiService, teamkatalogenService, adminAuthorizationService)

        val userContext = userContextService.getUserContext("notfound@external.com")

        assertEquals("notfound@external.com", userContext.email)
        assertEquals(UserRole.NONE, userContext.role)
        assertEquals(emptyList(), userContext.teams)
    }

    @Test
    fun `should assign LEADER role when user has cluster membership with subteams`() = runTest {
        val mockHttpClient = HttpClient(MockEngine) {
            engine {
                addHandler { request ->
                    when {
                        request.url.encodedPath == "/member/membership/byUserEmail" -> {
                            val responseData = TeamkatalogenApiResponse(
                                teams = emptyList(),
                                clusters = listOf(
                                    no.nav.tpt.infrastructure.teamkatalogen.ClusterMembership(
                                        id = "cluster-123",
                                        name = "Security Cluster"
                                    )
                                ),
                                productAreas = emptyList()
                            )
                            val json = Json {
                                ignoreUnknownKeys = true
                            }
                            respond(
                                content = ByteReadChannel(json.encodeToString(TeamkatalogenApiResponse.serializer(), responseData)),
                                status = HttpStatusCode.OK,
                                headers = headersOf(HttpHeaders.ContentType, "application/json")
                            )
                        }
                        request.url.encodedPath == "/team" && request.url.parameters["clusterId"] == "cluster-123" -> {
                            val responseData = no.nav.tpt.infrastructure.teamkatalogen.SubteamsResponse(
                                content = listOf(
                                    no.nav.tpt.infrastructure.teamkatalogen.SubteamData(
                                        naisTeams = listOf("appsec", "security-team")
                                    ),
                                    no.nav.tpt.infrastructure.teamkatalogen.SubteamData(
                                        naisTeams = listOf("identity-team")
                                    )
                                )
                            )
                            val json = Json {
                                ignoreUnknownKeys = true
                            }
                            respond(
                                content = ByteReadChannel(json.encodeToString(no.nav.tpt.infrastructure.teamkatalogen.SubteamsResponse.serializer(), responseData)),
                                status = HttpStatusCode.OK,
                                headers = headersOf(HttpHeaders.ContentType, "application/json")
                            )
                        }
                        else -> error("Unhandled ${request.url}")
                    }
                }
            }
            install(io.ktor.client.plugins.contentnegotiation.ContentNegotiation) {
                json(Json {
                    ignoreUnknownKeys = true
                })
            }
        }

        val naisApiService = object : NaisApiService {
            override suspend fun getAllTeams(): List<TeamInfo> = emptyList()
            override suspend fun getVulnerabilitiesForUser(email: String) = UserVulnerabilitiesData(teams = emptyList())
            override suspend fun getVulnerabilitiesForTeam(teamSlug: String) = UserVulnerabilitiesData(teams = emptyList())
            override suspend fun getTeamMembershipsForUser(email: String) = emptyList<String>()
        }

        val teamkatalogenClient = TeamkatalogenClient(mockHttpClient, "https://teamkatalogen.nav.no")
        val teamkatalogenService = TeamkatalogenServiceImpl(teamkatalogenClient)
        val adminAuthorizationService = AdminAuthorizationServiceImpl("admin-group-1,admin-group-2")
        val userContextService = UserContextServiceImpl(naisApiService, teamkatalogenService, adminAuthorizationService)

        val userContext = userContextService.getUserContext("leader@nav.no")

        assertEquals("leader@nav.no", userContext.email)
        assertEquals(UserRole.LEADER, userContext.role)
        assertEquals(3, userContext.teams.size)
        assertEquals(true, userContext.teams.contains("appsec"))
        assertEquals(true, userContext.teams.contains("security-team"))
        assertEquals(true, userContext.teams.contains("identity-team"))
    }

    @Test
    fun `should assign LEADER role when user has productArea membership with subteams`() = runTest {
        val mockHttpClient = HttpClient(MockEngine) {
            engine {
                addHandler { request ->
                    when {
                        request.url.encodedPath == "/member/membership/byUserEmail" -> {
                            val responseData = TeamkatalogenApiResponse(
                                teams = emptyList(),
                                clusters = emptyList(),
                                productAreas = listOf(
                                    no.nav.tpt.infrastructure.teamkatalogen.ProductAreaMembership(
                                        id = "pa-456",
                                        name = "Security Product Area"
                                    )
                                )
                            )
                            val json = Json { ignoreUnknownKeys = true }
                            respond(
                                content = ByteReadChannel(json.encodeToString(TeamkatalogenApiResponse.serializer(), responseData)),
                                status = HttpStatusCode.OK,
                                headers = headersOf(HttpHeaders.ContentType, "application/json")
                            )
                        }
                        request.url.encodedPath == "/team" && request.url.parameters["productAreaId"] == "pa-456" -> {
                            val responseData = no.nav.tpt.infrastructure.teamkatalogen.SubteamsResponse(
                                content = listOf(
                                    no.nav.tpt.infrastructure.teamkatalogen.SubteamData(
                                        naisTeams = listOf("team-data", "team-analytics")
                                    )
                                )
                            )
                            val json = Json { ignoreUnknownKeys = true }
                            respond(
                                content = ByteReadChannel(json.encodeToString(no.nav.tpt.infrastructure.teamkatalogen.SubteamsResponse.serializer(), responseData)),
                                status = HttpStatusCode.OK,
                                headers = headersOf(HttpHeaders.ContentType, "application/json")
                            )
                        }
                        else -> error("Unhandled ${request.url}")
                    }
                }
            }
            install(io.ktor.client.plugins.contentnegotiation.ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val naisApiService = object : NaisApiService {
            override suspend fun getAllTeams(): List<TeamInfo> = emptyList()
            override suspend fun getVulnerabilitiesForUser(email: String) = UserVulnerabilitiesData(teams = emptyList())
            override suspend fun getVulnerabilitiesForTeam(teamSlug: String) = UserVulnerabilitiesData(teams = emptyList())
            override suspend fun getTeamMembershipsForUser(email: String) = emptyList<String>()
        }

        val teamkatalogenClient = TeamkatalogenClient(mockHttpClient, "https://teamkatalogen.nav.no")
        val teamkatalogenService = TeamkatalogenServiceImpl(teamkatalogenClient)
        val adminAuthorizationService = AdminAuthorizationServiceImpl("admin-group-1,admin-group-2")
        val userContextService = UserContextServiceImpl(naisApiService, teamkatalogenService, adminAuthorizationService)

        val userContext = userContextService.getUserContext("pa-leader@nav.no")

        assertEquals("pa-leader@nav.no", userContext.email)
        assertEquals(UserRole.LEADER, userContext.role)
        assertEquals(listOf("team-data", "team-analytics"), userContext.teams)
    }

    @Test
    fun `should assign NONE role when user has cluster but subteams have no naisTeams`() = runTest {
        val mockHttpClient = HttpClient(MockEngine) {
            engine {
                addHandler { request ->
                    when {
                        request.url.encodedPath == "/member/membership/byUserEmail" -> {
                            val responseData = TeamkatalogenApiResponse(
                                teams = emptyList(),
                                clusters = listOf(
                                    no.nav.tpt.infrastructure.teamkatalogen.ClusterMembership(id = "empty-cluster")
                                ),
                                productAreas = emptyList()
                            )
                            val json = Json { ignoreUnknownKeys = true }
                            respond(
                                content = ByteReadChannel(json.encodeToString(TeamkatalogenApiResponse.serializer(), responseData)),
                                status = HttpStatusCode.OK,
                                headers = headersOf(HttpHeaders.ContentType, "application/json")
                            )
                        }
                        request.url.encodedPath == "/team" -> {
                            val responseData = no.nav.tpt.infrastructure.teamkatalogen.SubteamsResponse(
                                content = listOf(
                                    no.nav.tpt.infrastructure.teamkatalogen.SubteamData(
                                        naisTeams = emptyList()
                                    )
                                )
                            )
                            val json = Json { ignoreUnknownKeys = true }
                            respond(
                                content = ByteReadChannel(json.encodeToString(no.nav.tpt.infrastructure.teamkatalogen.SubteamsResponse.serializer(), responseData)),
                                status = HttpStatusCode.OK,
                                headers = headersOf(HttpHeaders.ContentType, "application/json")
                            )
                        }
                        else -> error("Unhandled ${request.url}")
                    }
                }
            }
            install(io.ktor.client.plugins.contentnegotiation.ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val naisApiService = object : NaisApiService {
            override suspend fun getAllTeams(): List<TeamInfo> = emptyList()
            override suspend fun getVulnerabilitiesForUser(email: String) = UserVulnerabilitiesData(teams = emptyList())
            override suspend fun getVulnerabilitiesForTeam(teamSlug: String) = UserVulnerabilitiesData(teams = emptyList())
            override suspend fun getTeamMembershipsForUser(email: String) = emptyList<String>()
        }

        val teamkatalogenClient = TeamkatalogenClient(mockHttpClient, "https://teamkatalogen.nav.no")
        val teamkatalogenService = TeamkatalogenServiceImpl(teamkatalogenClient)
        val adminAuthorizationService = AdminAuthorizationServiceImpl("admin-group-1,admin-group-2")
        val userContextService = UserContextServiceImpl(naisApiService, teamkatalogenService, adminAuthorizationService)

        val userContext = userContextService.getUserContext("empty@nav.no")

        assertEquals("empty@nav.no", userContext.email)
        assertEquals(UserRole.NONE, userContext.role)
        assertEquals(emptyList(), userContext.teams)
    }

    @Test
    fun `should return ADMIN role when user has admin group`() = runTest {
        val mockHttpClient = HttpClient(MockEngine) {
            engine {
                addHandler { request ->
                    when (request.url.encodedPath) {
                        "/query" -> respond(
                            content = ByteReadChannel("""{"data":{"teams":[]}}"""),
                            status = HttpStatusCode.OK,
                            headers = headersOf(HttpHeaders.ContentType, "application/json")
                        )
                        else -> error("Unhandled ${request.url.encodedPath}")
                    }
                }
            }
        }

        val naisApiService = object : NaisApiService {
            override suspend fun getAllTeams(): List<TeamInfo> = emptyList()
            override suspend fun getVulnerabilitiesForUser(email: String) = UserVulnerabilitiesData(teams = emptyList())
            override suspend fun getVulnerabilitiesForTeam(teamSlug: String) = UserVulnerabilitiesData(teams = emptyList())
            override suspend fun getTeamMembershipsForUser(email: String) = listOf("team-a", "team-b")
        }

        val teamkatalogenClient = TeamkatalogenClient(mockHttpClient, "https://teamkatalogen.nav.no")
        val teamkatalogenService = TeamkatalogenServiceImpl(teamkatalogenClient)
        val adminAuthorizationService = AdminAuthorizationServiceImpl("admin-group-1,admin-group-2")
        val userContextService = UserContextServiceImpl(naisApiService, teamkatalogenService, adminAuthorizationService)

        val userContext = userContextService.getUserContext("admin@nav.no", listOf("admin-group-1", "other-group"))

        assertEquals("admin@nav.no", userContext.email)
        assertEquals(UserRole.ADMIN, userContext.role)
        assertEquals(listOf("team-a", "team-b"), userContext.teams)
    }

    @Test
    fun `should prioritize ADMIN role over DEVELOPER when user has admin group`() = runTest {
        val mockHttpClient = HttpClient(MockEngine) {
            engine {
                addHandler { request ->
                    when (request.url.encodedPath) {
                        "/query" -> respond(
                            content = ByteReadChannel("""{"data":{"teams":[]}}"""),
                            status = HttpStatusCode.OK,
                            headers = headersOf(HttpHeaders.ContentType, "application/json")
                        )
                        else -> error("Unhandled ${request.url.encodedPath}")
                    }
                }
            }
        }

        val naisApiService = object : NaisApiService {
            override suspend fun getAllTeams(): List<TeamInfo> = emptyList()
            override suspend fun getVulnerabilitiesForUser(email: String) = UserVulnerabilitiesData(teams = emptyList())
            override suspend fun getVulnerabilitiesForTeam(teamSlug: String) = UserVulnerabilitiesData(teams = emptyList())
            override suspend fun getTeamMembershipsForUser(email: String) = listOf("dev-team")
        }

        val teamkatalogenClient = TeamkatalogenClient(mockHttpClient, "https://teamkatalogen.nav.no")
        val teamkatalogenService = TeamkatalogenServiceImpl(teamkatalogenClient)
        val adminAuthorizationService = AdminAuthorizationServiceImpl("admin-group")
        val userContextService = UserContextServiceImpl(naisApiService, teamkatalogenService, adminAuthorizationService)

        val userContext = userContextService.getUserContext("admin-dev@nav.no", listOf("admin-group"))

        assertEquals(UserRole.ADMIN, userContext.role)
        assertEquals(listOf("dev-team"), userContext.teams)
    }
}
