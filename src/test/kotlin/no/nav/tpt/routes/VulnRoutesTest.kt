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
    fun `should return 200 with vulnerabilities for authenticated user`() = testApplication {
        val tokenIntrospectionService = MockTokenIntrospectionService(
            shouldSucceed = true,
            navIdent = "test-ident",
            preferredUsername = "test@example.com"
        )

        val naisApiService = MockNaisApiService(
            shouldSucceed = true,
            mockUserVulnerabilitiesData = UserVulnerabilitiesData(
                teams = listOf(
                    TeamVulnerabilitiesData(
                        teamSlug = "team-alpha",
                        workloads = listOf(
                            WorkloadData(
                                id = "workload-1",
                                name = "app1",
                                workloadType = "app",
                                imageTag = "2024.01.15-10.30-abc123",
                                repository = "ghcr.io/navikt/app1",
                                environment = "production",
                                ingressTypes = listOf("EXTERNAL"),
                                vulnerabilities = listOf(
                                    VulnerabilityData(
                                        identifier = "CVE-2023-12345",
                                        severity = "HIGH",
                                        packageName = "test-package",
                                        description = "Test vulnerability",
                                        vulnerabilityDetailsLink = "https://nvd.nist.gov/vuln/detail/CVE-2023-12345",
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
        assertEquals(ContentType.Application.Json, response.contentType()?.withoutParameters())

        val vulnResponse = Json.decodeFromString<VulnResponse>(response.bodyAsText())
        assertEquals(1, vulnResponse.teams.size)

        val team = vulnResponse.teams[0]
        assertEquals("team-alpha", team.team)
        assertEquals(1, team.workloads.size)

        val workload = team.workloads[0]
        assertEquals("workload-1", workload.id)
        assertEquals("app1", workload.name)
        assertEquals("ghcr.io/navikt/app1", workload.repository)
        assertEquals("production", workload.environment)
        assertEquals(1, workload.vulnerabilities.size)

        val vuln = workload.vulnerabilities[0]
        assertEquals("CVE-2023-12345", vuln.identifier)
        assertEquals("test-package", vuln.packageName)
        assertNotNull(vuln.riskScore)
        assertTrue(vuln.riskScore > 0.0)
    }

    @Test
    fun `should return 200 with empty teams when user has no vulnerabilities`() = testApplication {
        val tokenIntrospectionService = MockTokenIntrospectionService(
            shouldSucceed = true,
            navIdent = "test-ident",
            preferredUsername = "test@example.com"
        )

        val naisApiService = MockNaisApiService(
            shouldSucceed = true,
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
    fun `should return 200 with multiple teams and workloads`() = testApplication {
        val tokenIntrospectionService = MockTokenIntrospectionService(
            shouldSucceed = true,
            navIdent = "test-ident",
            preferredUsername = "test@example.com"
        )

        val naisApiService = MockNaisApiService(
            shouldSucceed = true,
            mockUserVulnerabilitiesData = UserVulnerabilitiesData(
                teams = listOf(
                    TeamVulnerabilitiesData(
                        teamSlug = "team-one",
                        workloads = listOf(
                            WorkloadData(
                                id = "workload-1",
                                name = "app-a",
                                workloadType = "app",
                                imageTag = null,
                                repository = null,
                                environment = "production",
                                ingressTypes = listOf("EXTERNAL"),
                                vulnerabilities = listOf(
                                    VulnerabilityData(
                                        identifier = "CVE-2023-11111",
                                        severity = "LOW",
                                        packageName = "pkg-a",
                                        description = null,
                                        vulnerabilityDetailsLink = null,
                                        suppressed = false
                                    )
                                )
                            )
                        )
                    ),
                    TeamVulnerabilitiesData(
                        teamSlug = "team-two",
                        workloads = listOf(
                            WorkloadData(
                                id = "workload-2",
                                name = "app-b",
                                workloadType = "app",
                                imageTag = null,
                                repository = null,
                                environment = "production",
                                ingressTypes = listOf("INTERNAL"),
                                vulnerabilities = listOf(
                                    VulnerabilityData(
                                        identifier = "CVE-2023-22222",
                                        severity = "HIGH",
                                        packageName = "pkg-b",
                                        description = null,
                                        vulnerabilityDetailsLink = null,
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
                title = "Test",
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
        assertEquals("team-one", vulnResponse.teams[0].team)
        assertEquals("team-two", vulnResponse.teams[1].team)
        assertEquals(1, vulnResponse.teams[0].workloads.size)
        assertEquals(1, vulnResponse.teams[1].workloads.size)
    }

    @Test
    fun `should return 200 and include KEV flag when vulnerability is in KEV catalog`() = testApplication {
        val tokenIntrospectionService = MockTokenIntrospectionService(
            shouldSucceed = true,
            navIdent = "test-ident",
            preferredUsername = "test@example.com"
        )

        val naisApiService = MockNaisApiService(
            shouldSucceed = true,
            mockUserVulnerabilitiesData = UserVulnerabilitiesData(
                teams = listOf(
                    TeamVulnerabilitiesData(
                        teamSlug = "team-alpha",
                        workloads = listOf(
                            WorkloadData(
                                id = "workload-1",
                                name = "app1",
                                workloadType = "app",
                                imageTag = null,
                                repository = null,
                                environment = null,
                                ingressTypes = listOf("INTERNAL"),
                                vulnerabilities = listOf(
                                    VulnerabilityData(
                                        identifier = "CVE-2023-99999",
                                        severity = "CRITICAL",
                                        packageName = "vulnerable-lib",
                                        description = "KEV vulnerability",
                                        vulnerabilityDetailsLink = null,
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
                title = "Test KEV",
                catalogVersion = "1.0",
                dateReleased = "2023-01-01",
                count = 1,
                vulnerabilities = listOf(
                    KevVulnerability(
                        cveID = "CVE-2023-99999",
                        vendorProject = "Test",
                        product = "Test Product",
                        vulnerabilityName = "Test Vuln",
                        dateAdded = "2023-01-01",
                        shortDescription = "Test",
                        requiredAction = "Patch",
                        dueDate = "2023-12-31",
                        knownRansomwareCampaignUse = "Unknown",
                        notes = "",
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
        val vulnResponse = Json.decodeFromString<VulnResponse>(response.bodyAsText())
        val vuln = vulnResponse.teams[0].workloads[0].vulnerabilities[0]
        assertEquals("CVE-2023-99999", vuln.identifier)
        assertNotNull(vuln.riskScoreBreakdown)

        val hasKevFactor = vuln.riskScoreBreakdown?.factors?.any { it.name.contains("KEV", ignoreCase = true) } ?: false
        assertTrue(hasKevFactor, "Expected KEV factor in risk score breakdown")
    }

    @Test
    fun `should return 200 and respect bypassCache query parameter`() = testApplication {
        val tokenIntrospectionService = MockTokenIntrospectionService(
            shouldSucceed = true,
            navIdent = "test-ident",
            preferredUsername = "test@example.com"
        )

        val naisApiService = MockNaisApiService(
            shouldSucceed = true,
            mockUserVulnerabilitiesData = UserVulnerabilitiesData(
                teams = listOf(
                    TeamVulnerabilitiesData(
                        teamSlug = "team-alpha",
                        workloads = listOf(
                            WorkloadData(
                                id = "workload-1",
                                name = "app1",
                                workloadType = "app",
                                imageTag = null,
                                repository = null,
                                environment = null,
                                ingressTypes = listOf("INTERNAL"),
                                vulnerabilities = listOf(
                                    VulnerabilityData(
                                        identifier = "CVE-2023-12345",
                                        severity = "HIGH",
                                        packageName = null,
                                        description = null,
                                        vulnerabilityDetailsLink = null,
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
                title = "Test",
                catalogVersion = "1.0",
                dateReleased = "2023-01-01",
                count = 0,
                vulnerabilities = emptyList()
            )
        )

        application {
            testModule(tokenIntrospectionService, naisApiService, kevService)
        }

        val response = client.get("/vulnerabilities/user?bypassCache=true") {
            header(HttpHeaders.Authorization, "Bearer valid-token")
        }

        assertEquals(HttpStatusCode.OK, response.status)
        val vulnResponse = Json.decodeFromString<VulnResponse>(response.bodyAsText())
        assertEquals(1, vulnResponse.teams.size)
    }

    @Test
    fun `should include workloadType field in response`() = testApplication {
        val tokenIntrospectionService = MockTokenIntrospectionService(
            shouldSucceed = true,
            navIdent = "test-ident",
            preferredUsername = "test@example.com"
        )

        val naisApiService = MockNaisApiService(
            shouldSucceed = true,
            mockUserVulnerabilitiesData = UserVulnerabilitiesData(
                teams = listOf(
                    TeamVulnerabilitiesData(
                        teamSlug = "team-test",
                        workloads = listOf(
                            WorkloadData(
                                id = "workload-app",
                                name = "test-application",
                                workloadType = "app",
                                imageTag = "1.0.0",
                                repository = "ghcr.io/navikt/test-app",
                                environment = "production",
                                ingressTypes = listOf("EXTERNAL"),
                                vulnerabilities = listOf(
                                    VulnerabilityData(
                                        identifier = "CVE-2024-00001",
                                        severity = "HIGH",
                                        packageName = "test-pkg",
                                        description = "Test vulnerability",
                                        vulnerabilityDetailsLink = "https://nvd.nist.gov/vuln/detail/CVE-2024-00001",
                                        suppressed = false
                                    )
                                )
                            ),
                            WorkloadData(
                                id = "workload-job",
                                name = "test-job",
                                workloadType = "job",
                                imageTag = "1.0.0",
                                repository = "ghcr.io/navikt/test-job",
                                environment = "production",
                                ingressTypes = emptyList(),
                                vulnerabilities = listOf(
                                    VulnerabilityData(
                                        identifier = "CVE-2024-00002",
                                        severity = "MEDIUM",
                                        packageName = "another-pkg",
                                        description = "Another test vulnerability",
                                        vulnerabilityDetailsLink = "https://nvd.nist.gov/vuln/detail/CVE-2024-00002",
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
        assertEquals(ContentType.Application.Json, response.contentType()?.withoutParameters())

        val vulnResponse = Json.decodeFromString<VulnResponse>(response.bodyAsText())
        assertEquals(1, vulnResponse.teams.size)

        val team = vulnResponse.teams[0]
        assertEquals("team-test", team.team)
        assertEquals(2, team.workloads.size)

        val appWorkload = team.workloads.find { it.name == "test-application" }
        assertNotNull(appWorkload, "Application workload should be present")
        assertEquals("workload-app", appWorkload.id)
        assertEquals("app", appWorkload.workloadType)
        assertEquals("ghcr.io/navikt/test-app", appWorkload.repository)

        val jobWorkload = team.workloads.find { it.name == "test-job" }
        assertNotNull(jobWorkload, "Job workload should be present")
        assertEquals("workload-job", jobWorkload.id)
        assertEquals("job", jobWorkload.workloadType)
        assertEquals("ghcr.io/navikt/test-job", jobWorkload.repository)
    }
}

