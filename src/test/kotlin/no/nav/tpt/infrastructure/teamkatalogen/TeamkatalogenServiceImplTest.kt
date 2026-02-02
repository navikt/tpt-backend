package no.nav.tpt.infrastructure.teamkatalogen

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.utils.io.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TeamkatalogenServiceImplTest {

    private fun createMockClient(
        membershipResponseJson: String,
        subteamResponses: Map<String, String>
    ): HttpClient {
        return HttpClient(MockEngine) {
            engine {
                addHandler { request ->
                    when {
                        request.url.encodedPath == "/member/membership/byUserEmail" -> {
                            respond(
                                content = ByteReadChannel(membershipResponseJson),
                                status = HttpStatusCode.OK,
                                headers = headersOf(HttpHeaders.ContentType, "application/json")
                            )
                        }
                        request.url.encodedPath == "/team" -> {
                            val productAreaId = request.url.parameters["productAreaId"]
                            val clusterId = request.url.parameters["clusterId"]
                            val key = productAreaId ?: clusterId
                            val response = subteamResponses[key]
                                ?: error("No mock response for productAreaId=$productAreaId, clusterId=$clusterId")
                            
                            respond(
                                content = ByteReadChannel(response),
                                status = HttpStatusCode.OK,
                                headers = headersOf(HttpHeaders.ContentType, "application/json")
                            )
                        }
                        else -> error("Unhandled ${request.url}")
                    }
                }
            }
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }
    }

    @Test
    fun `should fetch NAIS teams using productAreaId from cluster`() = runTest {
        val membershipJson = """
            {
                "teams": [],
                "clusters": [
                    {"id": "cluster-123", "name": "Security Cluster", "productAreaId": "pa-from-cluster"}
                ],
                "productAreas": []
            }
        """

        val subteamResponses = mapOf(
            "pa-from-cluster" to """
                {
                    "content": [
                        {"id": "team-1", "naisTeams": ["appsec", "security-team"]},
                        {"id": "team-2", "naisTeams": ["identity-team"]}
                    ]
                }
            """
        )

        val httpClient = createMockClient(membershipJson, subteamResponses)
        val client = TeamkatalogenClient(httpClient, "https://teamkatalogen.test")
        val service = TeamkatalogenServiceImpl(client)

        val membership = client.getMembershipByEmail("user@nav.no")
        val naisTeams = service.getSubteamNaisTeams(
            membership.clusterIds,
            membership.clusterProductAreaIds + membership.productAreaIds
        )

        assertEquals(3, naisTeams.size)
        assertTrue(naisTeams.containsAll(listOf("appsec", "security-team", "identity-team")))
    }

    @Test
    fun `should fetch NAIS teams from direct productArea`() = runTest {
        val membershipJson = """
            {
                "teams": [],
                "clusters": [],
                "productAreas": [
                    {"id": "pa-456", "name": "Data Product Area"}
                ]
            }
        """

        val subteamResponses = mapOf(
            "pa-456" to """
                {
                    "content": [
                        {"id": "team-3", "naisTeams": ["data-team", "analytics-team"]}
                    ]
                }
            """
        )

        val httpClient = createMockClient(membershipJson, subteamResponses)
        val client = TeamkatalogenClient(httpClient, "https://teamkatalogen.test")
        val service = TeamkatalogenServiceImpl(client)

        val membership = client.getMembershipByEmail("user@nav.no")
        val naisTeams = service.getSubteamNaisTeams(
            membership.clusterIds,
            membership.clusterProductAreaIds + membership.productAreaIds
        )

        assertEquals(2, naisTeams.size)
        assertTrue(naisTeams.containsAll(listOf("data-team", "analytics-team")))
    }

    @Test
    fun `should fetch NAIS teams from both cluster and direct productArea`() = runTest {
        val membershipJson = """
            {
                "teams": [],
                "clusters": [
                    {"id": "cluster-1", "name": "Cluster 1", "productAreaId": "pa-from-cluster"}
                ],
                "productAreas": [
                    {"id": "pa-1", "name": "Product Area 1"}
                ]
            }
        """

        val subteamResponses = mapOf(
            "pa-from-cluster" to """
                {
                    "content": [
                        {"id": "team-1", "naisTeams": ["team-a", "team-b"]}
                    ]
                }
            """,
            "pa-1" to """
                {
                    "content": [
                        {"id": "team-2", "naisTeams": ["team-c", "team-d"]}
                    ]
                }
            """
        )

        val httpClient = createMockClient(membershipJson, subteamResponses)
        val client = TeamkatalogenClient(httpClient, "https://teamkatalogen.test")
        val service = TeamkatalogenServiceImpl(client)

        val membership = client.getMembershipByEmail("user@nav.no")
        val naisTeams = service.getSubteamNaisTeams(
            membership.clusterIds,
            membership.clusterProductAreaIds + membership.productAreaIds
        )

        assertEquals(4, naisTeams.size)
        assertTrue(naisTeams.containsAll(listOf("team-a", "team-b", "team-c", "team-d")))
    }

    @Test
    fun `should deduplicate productAreaIds from multiple clusters`() = runTest {
        val membershipJson = """
            {
                "teams": [],
                "clusters": [
                    {"id": "cluster-1", "productAreaId": "pa-shared"},
                    {"id": "cluster-2", "productAreaId": "pa-shared"}
                ],
                "productAreas": []
            }
        """

        val subteamResponses = mapOf(
            "pa-shared" to """
                {
                    "content": [
                        {"id": "team-1", "naisTeams": ["appsec", "security-team"]}
                    ]
                }
            """
        )

        val httpClient = createMockClient(membershipJson, subteamResponses)
        val client = TeamkatalogenClient(httpClient, "https://teamkatalogen.test")
        val service = TeamkatalogenServiceImpl(client)

        val membership = client.getMembershipByEmail("user@nav.no")
        val allProductAreaIds = membership.clusterProductAreaIds + membership.productAreaIds
        
        // Should only fetch once despite two clusters pointing to same productArea
        assertEquals(1, allProductAreaIds.distinct().size)
        
        val naisTeams = service.getSubteamNaisTeams(
            membership.clusterIds,
            allProductAreaIds
        )
        assertEquals(2, naisTeams.size)
        assertTrue(naisTeams.containsAll(listOf("appsec", "security-team")))
    }

    @Test
    fun `should return empty list when subteams have no NAIS teams`() = runTest {
        val membershipJson = """
            {
                "teams": [],
                "clusters": [
                    {"id": "cluster-1", "productAreaId": "pa-1"}
                ],
                "productAreas": []
            }
        """

        val subteamResponses = mapOf(
            "pa-1" to """
                {
                    "content": [
                        {"id": "team-1", "naisTeams": []}
                    ]
                }
            """
        )

        val httpClient = createMockClient(membershipJson, subteamResponses)
        val client = TeamkatalogenClient(httpClient, "https://teamkatalogen.test")
        val service = TeamkatalogenServiceImpl(client)

        val membership = client.getMembershipByEmail("user@nav.no")
        val naisTeams = service.getSubteamNaisTeams(
            membership.clusterIds,
            membership.clusterProductAreaIds + membership.productAreaIds
        )

        assertTrue(naisTeams.isEmpty())
    }

    @Test
    fun `should handle empty response`() = runTest {
        val membershipJson = """
            {
                "teams": [],
                "clusters": [],
                "productAreas": []
            }
        """

        val httpClient = createMockClient(membershipJson, emptyMap())
        val client = TeamkatalogenClient(httpClient, "https://teamkatalogen.test")
        val service = TeamkatalogenServiceImpl(client)

        val membership = client.getMembershipByEmail("user@nav.no")
        val naisTeams = service.getSubteamNaisTeams(
            membership.clusterIds,
            membership.clusterProductAreaIds + membership.productAreaIds
        )

        assertTrue(naisTeams.isEmpty())
    }
}
