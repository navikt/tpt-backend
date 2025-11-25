package no.nav.tpt.infrastructure.vulns

import kotlinx.coroutines.test.runTest
import no.nav.tpt.infrastructure.cisa.KevCatalog
import no.nav.tpt.infrastructure.cisa.KevService
import no.nav.tpt.infrastructure.cisa.KevVulnerability
import no.nav.tpt.infrastructure.epss.MockEpssService
import no.nav.tpt.infrastructure.nais.*
import kotlin.test.*

class VulnServiceTest {

    @Test
    fun `should combine data from all sources successfully`() = runTest {
        val mockNaisApiService = MockNaisApiService(
            shouldSucceed = true,
            mockUserApplicationsData = UserApplicationsData(
                teams = listOf(
                    TeamApplicationsData(
                        teamSlug = "team-alpha",
                        applications = listOf(
                            ApplicationData(name = "app1", ingressTypes = listOf(IngressType.INTERNAL, IngressType.EXTERNAL)),
                            ApplicationData(name = "app2", ingressTypes = listOf(IngressType.INTERNAL))
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
                                imageTag = null,
                                vulnerabilities = listOf(
                                    VulnerabilityData(
                                        identifier = "CVE-2023-12345",
                                        severity = "HIGH",
                                        suppressed = false
                                    ),
                                    VulnerabilityData(
                                        identifier = "CVE-2023-54321",
                                        severity = "MEDIUM",
                                        suppressed = true
                                    )
                                )
                            )
                        )
                    )
                )
            )
        )

        val mockKevService = object : KevService {
            override suspend fun getKevCatalog(): KevCatalog {
                return KevCatalog(
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
            }
        }

        val vulnService = VulnServiceImpl(mockNaisApiService, mockKevService, MockEpssService())
        val result = vulnService.fetchVulnerabilitiesForUser("test@example.com")

        assertEquals(1, result.teams.size)
        assertEquals("team-alpha", result.teams[0].team)
        assertEquals(1, result.teams[0].workloads.size)
        assertEquals("app1", result.teams[0].workloads[0].name)
        assertEquals(listOf("INTERNAL", "EXTERNAL"), result.teams[0].workloads[0].ingressTypes)
        assertEquals(2, result.teams[0].workloads[0].vulnerabilities.size)

        val highVuln = result.teams[0].workloads[0].vulnerabilities.find { it.identifier == "CVE-2023-12345" }
        assertNotNull(highVuln)
        assertEquals("HIGH", highVuln.severity)
        assertFalse(highVuln.suppressed)
        assertTrue(highVuln.hasKevEntry)

        val mediumVuln = result.teams[0].workloads[0].vulnerabilities.find { it.identifier == "CVE-2023-54321" }
        assertNotNull(mediumVuln)
        assertEquals("MEDIUM", mediumVuln.severity)
        assertTrue(mediumVuln.suppressed)
        assertFalse(mediumVuln.hasKevEntry)
    }

    @Test
    fun `should filter out workloads with no vulnerabilities`() = runTest {
        val mockNaisApiService = MockNaisApiService(
            shouldSucceed = true,
            mockUserApplicationsData = UserApplicationsData(
                teams = listOf(
                    TeamApplicationsData(
                        teamSlug = "team-beta",
                        applications = listOf(
                            ApplicationData(name = "app1", ingressTypes = listOf(IngressType.INTERNAL))
                        )
                    )
                )
            ),
            mockUserVulnerabilitiesData = UserVulnerabilitiesData(
                teams = listOf(
                    TeamVulnerabilitiesData(
                        teamSlug = "team-beta",
                        workloads = listOf(
                            WorkloadData(id = "workload-2", name = "app1", imageTag = null, vulnerabilities = emptyList())
                        )
                    )
                )
            )
        )

        val mockKevService = object : KevService {
            override suspend fun getKevCatalog() = KevCatalog(
                title = "Test KEV Catalog",
                catalogVersion = "1.0",
                dateReleased = "2023-01-01",
                count = 0,
                vulnerabilities = emptyList()
            )
        }

        val vulnService = VulnServiceImpl(mockNaisApiService, mockKevService, MockEpssService())
        val result = vulnService.fetchVulnerabilitiesForUser("test@example.com")

        assertTrue(result.teams.isEmpty())
    }

    @Test
    fun `should filter out teams with no workloads`() = runTest {
        val mockNaisApiService = MockNaisApiService(
            shouldSucceed = true,
            mockUserApplicationsData = UserApplicationsData(teams = emptyList()),
            mockUserVulnerabilitiesData = UserVulnerabilitiesData(
                teams = listOf(
                    TeamVulnerabilitiesData(teamSlug = "team-gamma", workloads = emptyList())
                )
            )
        )

        val mockKevService = object : KevService {
            override suspend fun getKevCatalog() = KevCatalog(
                title = "Test KEV Catalog",
                catalogVersion = "1.0",
                dateReleased = "2023-01-01",
                count = 0,
                vulnerabilities = emptyList()
            )
        }

        val vulnService = VulnServiceImpl(mockNaisApiService, mockKevService, MockEpssService())
        val result = vulnService.fetchVulnerabilitiesForUser("test@example.com")

        assertTrue(result.teams.isEmpty())
    }

    @Test
    fun `should handle workloads without matching applications`() = runTest {
        val mockNaisApiService = MockNaisApiService(
            shouldSucceed = true,
            mockUserApplicationsData = UserApplicationsData(
                teams = listOf(
                    TeamApplicationsData(teamSlug = "team-delta", applications = emptyList())
                )
            ),
            mockUserVulnerabilitiesData = UserVulnerabilitiesData(
                teams = listOf(
                    TeamVulnerabilitiesData(
                        teamSlug = "team-delta",
                        workloads = listOf(
                            WorkloadData(
                                id = "workload-3",
                                name = "unknown-app",
                                imageTag = null,
                                vulnerabilities = listOf(
                                    VulnerabilityData(
                                        identifier = "CVE-2023-99999",
                                        severity = "CRITICAL",
                                        suppressed = false
                                    )
                                )
                            )
                        )
                    )
                )
            )
        )

        val mockKevService = object : KevService {
            override suspend fun getKevCatalog() = KevCatalog(
                title = "Test KEV Catalog",
                catalogVersion = "1.0",
                dateReleased = "2023-01-01",
                count = 0,
                vulnerabilities = emptyList()
            )
        }

        val vulnService = VulnServiceImpl(mockNaisApiService, mockKevService, MockEpssService())
        val result = vulnService.fetchVulnerabilitiesForUser("test@example.com")

        assertEquals(1, result.teams.size)
        assertEquals(1, result.teams[0].workloads.size)
        assertEquals("unknown-app", result.teams[0].workloads[0].name)
        assertEquals(emptyList(), result.teams[0].workloads[0].ingressTypes)
    }

    @Test
    fun `should handle multiple teams with multiple workloads`() = runTest {
        val mockNaisApiService = MockNaisApiService(
            shouldSucceed = true,
            mockUserApplicationsData = UserApplicationsData(
                teams = listOf(
                    TeamApplicationsData(
                        teamSlug = "team-one",
                        applications = listOf(
                            ApplicationData(name = "app-a", ingressTypes = listOf(IngressType.EXTERNAL))
                        )
                    ),
                    TeamApplicationsData(
                        teamSlug = "team-two",
                        applications = listOf(
                            ApplicationData(name = "app-b", ingressTypes = listOf(IngressType.INTERNAL))
                        )
                    )
                )
            ),
            mockUserVulnerabilitiesData = UserVulnerabilitiesData(
                teams = listOf(
                    TeamVulnerabilitiesData(
                        teamSlug = "team-one",
                        workloads = listOf(
                            WorkloadData(
                                id = "workload-4",
                                name = "app-a",
                                imageTag = null,
                                vulnerabilities = listOf(
                                    VulnerabilityData(
                                        identifier = "CVE-2023-11111",
                                        severity = "LOW",
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
                                id = "workload-5",
                                name = "app-b",
                                imageTag = null,
                                vulnerabilities = listOf(
                                    VulnerabilityData(
                                        identifier = "CVE-2023-22222",
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

        val mockKevService = object : KevService {
            override suspend fun getKevCatalog() = KevCatalog(
                title = "Test KEV Catalog",
                catalogVersion = "1.0",
                dateReleased = "2023-01-01",
                count = 1,
                vulnerabilities = listOf(
                    KevVulnerability(
                        cveID = "CVE-2023-22222",
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
        }

        val vulnService = VulnServiceImpl(mockNaisApiService, mockKevService, MockEpssService())
        val result = vulnService.fetchVulnerabilitiesForUser("test@example.com")

        assertEquals(2, result.teams.size)

        val teamOne = result.teams.find { it.team == "team-one" }
        assertNotNull(teamOne)
        assertEquals(1, teamOne.workloads.size)
        assertFalse(teamOne.workloads[0].vulnerabilities[0].hasKevEntry)

        val teamTwo = result.teams.find { it.team == "team-two" }
        assertNotNull(teamTwo)
        assertEquals(1, teamTwo.workloads.size)
        assertTrue(teamTwo.workloads[0].vulnerabilities[0].hasKevEntry)
    }

    @Test
    fun `should return empty response when no vulnerabilities exist`() = runTest {
        val mockNaisApiService = MockNaisApiService(
            shouldSucceed = true,
            mockUserApplicationsData = UserApplicationsData(teams = emptyList()),
            mockUserVulnerabilitiesData = UserVulnerabilitiesData(teams = emptyList())
        )

        val mockKevService = object : KevService {
            override suspend fun getKevCatalog() = KevCatalog(
                title = "Test KEV Catalog",
                catalogVersion = "1.0",
                dateReleased = "2023-01-01",
                count = 0,
                vulnerabilities = emptyList()
            )
        }

        val vulnService = VulnServiceImpl(mockNaisApiService, mockKevService, MockEpssService())
        val result = vulnService.fetchVulnerabilitiesForUser("test@example.com")

        assertEquals(0, result.teams.size)
    }
}

