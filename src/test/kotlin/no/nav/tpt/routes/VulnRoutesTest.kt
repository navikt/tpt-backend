package no.nav.tpt.routes

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.Json
import no.nav.tpt.domain.ProblemDetail
import no.nav.tpt.domain.VulnResponse
import no.nav.tpt.infrastructure.auth.MockTokenIntrospectionService
import no.nav.tpt.infrastructure.cisa.KevCatalog
import no.nav.tpt.infrastructure.cisa.KevService
import no.nav.tpt.infrastructure.cisa.KevVulnerability
import no.nav.tpt.infrastructure.nais.*
import no.nav.tpt.plugins.testModule
import kotlin.test.*

class MockKevService(private val catalog: KevCatalog) : KevService {
    override suspend fun getKevCatalog() = catalog
}

class VulnRoutesTest {

    @Test
    fun `should return vulnerabilities for authenticated user`() = testApplication {
        val tokenIntrospectionService = MockTokenIntrospectionService(
            shouldSucceed = true,
            navIdent = "test-ident",
            preferredUsername = "test@example.com"
        )

        val naisApiService = MockNaisApiService(
            shouldSucceed = true,
            mockUserApplicationsData = UserApplicationsData(
                teams = listOf(
                    TeamApplicationsData(
                        teamSlug = "team-alpha",
                        applications = listOf(
                            ApplicationData(name = "app1", ingressTypes = listOf("internal"))
                        )
                    )
                )
            ),
            mockUserVulnerabilitiesData = UserVulnerabilitiesData(
                teams = listOf(
                    TeamVulnerabilitiesData(
                        teamSlug = "team-alpha",
                        workloads = listOf(
                            WorkloadData(
                                id = "workload-1",
                                name = "app1",
                                vulnerabilities = listOf(
                                    VulnerabilityData(
                                        identifier = "CVE-2023-12345",
                                        severity = "HIGH",
                                        suppressed = false
                                    )
                                )
                            )
                        )
                    )
                )
            )
        )

        val kevService = MockKevService(
            KevCatalog(
                title = "Test KEV Catalog",
                catalogVersion = "1.0",
                dateReleased = "2023-01-01",
                count = 1,
                vulnerabilities = listOf(
                    KevVulnerability(
                        cveID = "CVE-2023-12345",
                        vendorProject = "Test Vendor",
                        product = "Test Product",
                        vulnerabilityName = "Test Vulnerability",
                        dateAdded = "2023-01-01",
                        shortDescription = "Test description",
                        requiredAction = "Test action",
                        dueDate = "2023-12-31",
                        knownRansomwareCampaignUse = "Unknown",
                        notes = "Test notes",
                        cwes = emptyList()
                    )
                )
            )
        )

        application {
            testModule(tokenIntrospectionService, naisApiService, kevService)
        }

        val response = client.get("/vulnerabilities/user") {
            header(HttpHeaders.Authorization, "Bearer valid-token")
        }

        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(ContentType.Application.Json, response.contentType()?.withoutParameters())

        val vulnResponse = Json.decodeFromString<VulnResponse>(response.bodyAsText())
        assertEquals(1, vulnResponse.teams.size)
        assertEquals("team-alpha", vulnResponse.teams[0].team)
        assertEquals(1, vulnResponse.teams[0].workloads.size)
        assertEquals("app1", vulnResponse.teams[0].workloads[0].name)
        assertEquals(1, vulnResponse.teams[0].workloads[0].vulnerabilities.size)
        assertEquals("CVE-2023-12345", vulnResponse.teams[0].workloads[0].vulnerabilities[0].identifier)
        assertTrue(vulnResponse.teams[0].workloads[0].vulnerabilities[0].hasKevEntry)
    }

    @Test
    fun `should return 401 when no authorization header provided`() = testApplication {
        application {
            testModule()
        }

        val response = client.get("/vulnerabilities/user")

        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `should return 401 when token is invalid`() = testApplication {
        val tokenIntrospectionService = MockTokenIntrospectionService(shouldSucceed = false)

        application {
            testModule(tokenIntrospectionService)
        }

        val response = client.get("/vulnerabilities/user") {
            header(HttpHeaders.Authorization, "Bearer invalid-token")
        }

        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `should return 400 when preferred_username claim is missing`() = testApplication {
        val tokenIntrospectionService = MockTokenIntrospectionService(
            shouldSucceed = true,
            navIdent = "test-ident",
            preferredUsername = null
        )

        application {
            testModule(tokenIntrospectionService)
        }

        val response = client.get("/vulnerabilities/user") {
            header(HttpHeaders.Authorization, "Bearer valid-token")
        }

        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertEquals(ContentType.Application.Json, response.contentType()?.withoutParameters())

        val problemDetail = Json.decodeFromString<ProblemDetail>(response.bodyAsText())
        assertEquals("about:blank", problemDetail.type)
        assertEquals("Bad Request", problemDetail.title)
        assertEquals(400, problemDetail.status)
        assertEquals("preferred_username claim not found in token", problemDetail.detail)
        assertEquals("/vulnerabilities/user", problemDetail.instance)
    }

    @Test
    fun `should return 500 when service throws exception`() = testApplication {
        val tokenIntrospectionService = MockTokenIntrospectionService(
            shouldSucceed = true,
            navIdent = "test-ident",
            preferredUsername = "test@example.com"
        )

        val naisApiService = MockNaisApiService(shouldSucceed = false)

        application {
            testModule(tokenIntrospectionService, naisApiService)
        }

        val response = client.get("/vulnerabilities/user") {
            header(HttpHeaders.Authorization, "Bearer valid-token")
        }

        assertEquals(HttpStatusCode.InternalServerError, response.status)
        assertEquals(ContentType.Application.Json, response.contentType()?.withoutParameters())

        val problemDetail = Json.decodeFromString<ProblemDetail>(response.bodyAsText())
        assertEquals("about:blank", problemDetail.type)
        assertEquals("Internal Server Error", problemDetail.title)
        assertEquals(500, problemDetail.status)
        assertTrue(problemDetail.detail?.contains("Failed to fetch vulnerabilities") ?: false)
        assertEquals("/vulnerabilities/user", problemDetail.instance)
    }

    @Test
    fun `should return empty teams when user has no vulnerabilities`() = testApplication {
        val tokenIntrospectionService = MockTokenIntrospectionService(
            shouldSucceed = true,
            navIdent = "test-ident",
            preferredUsername = "test@example.com"
        )

        val naisApiService = MockNaisApiService(
            shouldSucceed = true,
            mockUserApplicationsData = UserApplicationsData(teams = emptyList()),
            mockUserVulnerabilitiesData = UserVulnerabilitiesData(teams = emptyList())
        )

        val kevService = MockKevService(
            KevCatalog(
                title = "Test KEV Catalog",
                catalogVersion = "1.0",
                dateReleased = "2023-01-01",
                count = 0,
                vulnerabilities = emptyList()
            )
        )

        application {
            testModule(tokenIntrospectionService, naisApiService, kevService)
        }

        val response = client.get("/vulnerabilities/user") {
            header(HttpHeaders.Authorization, "Bearer valid-token")
        }

        assertEquals(HttpStatusCode.OK, response.status)

        val vulnResponse = Json.decodeFromString<VulnResponse>(response.bodyAsText())
        assertEquals(0, vulnResponse.teams.size)
    }

    @Test
    fun `should handle multiple teams with vulnerabilities`() = testApplication {
        val tokenIntrospectionService = MockTokenIntrospectionService(
            shouldSucceed = true,
            navIdent = "test-ident",
            preferredUsername = "test@example.com"
        )

        val naisApiService = MockNaisApiService(
            shouldSucceed = true,
            mockUserApplicationsData = UserApplicationsData(
                teams = listOf(
                    TeamApplicationsData(
                        teamSlug = "team-one",
                        applications = listOf(ApplicationData(name = "app-a", ingressTypes = listOf("external")))
                    ),
                    TeamApplicationsData(
                        teamSlug = "team-two",
                        applications = listOf(ApplicationData(name = "app-b", ingressTypes = listOf("internal")))
                    )
                )
            ),
            mockUserVulnerabilitiesData = UserVulnerabilitiesData(
                teams = listOf(
                    TeamVulnerabilitiesData(
                        teamSlug = "team-one",
                        workloads = listOf(
                            WorkloadData(
                                id = "workload-2",
                                name = "app-a",
                                vulnerabilities = listOf(
                                    VulnerabilityData(identifier = "CVE-2023-11111", severity = "LOW", suppressed = false)
                                )
                            )
                        )
                    ),
                    TeamVulnerabilitiesData(
                        teamSlug = "team-two",
                        workloads = listOf(
                            WorkloadData(
                                id = "workload-3",
                                name = "app-b",
                                vulnerabilities = listOf(
                                    VulnerabilityData(identifier = "CVE-2023-22222", severity = "HIGH", suppressed = false)
                                )
                            )
                        )
                    )
                )
            )
        )

        val kevService = MockKevService(
            KevCatalog(
                title = "Test KEV Catalog",
                catalogVersion = "1.0",
                dateReleased = "2023-01-01",
                count = 0,
                vulnerabilities = emptyList()
            )
        )

        application {
            testModule(tokenIntrospectionService, naisApiService, kevService)
        }

        val response = client.get("/vulnerabilities/user") {
            header(HttpHeaders.Authorization, "Bearer valid-token")
        }

        assertEquals(HttpStatusCode.OK, response.status)

        val vulnResponse = Json.decodeFromString<VulnResponse>(response.bodyAsText())
        assertEquals(2, vulnResponse.teams.size)

        val teamOne = vulnResponse.teams.find { it.team == "team-one" }
        assertNotNull(teamOne)
        assertEquals(1, teamOne.workloads.size)

        val teamTwo = vulnResponse.teams.find { it.team == "team-two" }
        assertNotNull(teamTwo)
        assertEquals(1, teamTwo.workloads.size)
    }
}

