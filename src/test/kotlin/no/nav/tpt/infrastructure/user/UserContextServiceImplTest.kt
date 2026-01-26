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

        val userContextService = UserContextServiceImpl(naisApiService, teamkatalogenService)

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

        val userContextService = UserContextServiceImpl(naisApiService, teamkatalogenService)

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

        val userContextService = UserContextServiceImpl(naisApiService, teamkatalogenService)

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

        val userContextService = UserContextServiceImpl(naisApiService, teamkatalogenService)

        val userContext = userContextService.getUserContext("notfound@external.com")

        assertEquals("notfound@external.com", userContext.email)
        assertEquals(UserRole.NONE, userContext.role)
        assertEquals(emptyList(), userContext.teams)
    }
}
