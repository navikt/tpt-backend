package no.nav.tpt.infrastructure.vulns

import kotlinx.coroutines.test.runTest
import no.nav.tpt.domain.user.MockUserContextService
import no.nav.tpt.infrastructure.cisa.KevCatalog
import no.nav.tpt.infrastructure.cisa.KevService
import no.nav.tpt.infrastructure.cisa.KevVulnerability
import no.nav.tpt.infrastructure.epss.MockEpssService
import no.nav.tpt.infrastructure.github.MockGitHubRepository
import no.nav.tpt.infrastructure.nais.*
import no.nav.tpt.infrastructure.nvd.MockNvdRepository
import kotlin.test.*

class VulnServiceTest {

    @Test
    fun `should combine data from all sources successfully`() = runTest {
        val mockNaisApiService = MockNaisApiService(
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
                                environment = "prod",
                                ingressTypes = listOf("INTERNAL", "EXTERNAL"),
                                vulnerabilities = listOf(
                                    VulnerabilityData(
                                        identifier = "CVE-2023-12345",
                                        severity = "HIGH",
                                        packageName = null,
                                        description = null,
                                        vulnerabilityDetailsLink = null,
                                        suppressed = false
                                    ),
                                    VulnerabilityData(
                                        identifier = "CVE-2023-54321",
                                        severity = "MEDIUM",
                                        packageName = null,
                                        description = null,
                                        vulnerabilityDetailsLink = null,
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

        val riskScorer = no.nav.tpt.domain.risk.DefaultRiskScorer()
        val vulnerabilityDataService = no.nav.tpt.infrastructure.vulnerability.NaisApiVulnerabilityService(
            naisApiService = mockNaisApiService
        )
        val vulnService = VulnServiceImpl(
            vulnerabilityDataService = vulnerabilityDataService,
            kevService = mockKevService,
            epssService = MockEpssService(),
            nvdRepository = MockNvdRepository(),
            riskScorer = riskScorer,
            userContextService = MockUserContextService(mockTeams = listOf("team-alpha")),
            gitHubRepository = MockGitHubRepository()
        )
        val result = vulnService.fetchVulnerabilitiesForUser("test@example.com")

        assertEquals(1, result.teams.size)
        assertEquals("team-alpha", result.teams[0].team)
        assertEquals(1, result.teams[0].workloads.size)
        assertEquals("app1", result.teams[0].workloads[0].name)
        assertEquals(2, result.teams[0].workloads[0].vulnerabilities.size)
        assertTrue(result.teams[0].workloads[0].vulnerabilities[0].riskScore > 0)
    }

    @Test
    fun `should filter out workloads with no vulnerabilities`() = runTest {
        val mockNaisApiService = MockNaisApiService(
            shouldSucceed = true,
            mockUserVulnerabilitiesData = UserVulnerabilitiesData(
                teams = listOf(
                    TeamVulnerabilitiesData(
                        teamSlug = "team-beta",
                        workloads = listOf(
                            WorkloadData(
                                id = "workload-2",
                                name = "app1",
                                workloadType = "app",
                                imageTag = null,
                                repository = null,
                                environment = "production",
                                ingressTypes = listOf("INTERNAL"),
                                vulnerabilities = emptyList()
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

        val riskScorer = no.nav.tpt.domain.risk.DefaultRiskScorer()
        val vulnerabilityDataService = no.nav.tpt.infrastructure.vulnerability.NaisApiVulnerabilityService(
            naisApiService = mockNaisApiService
        )
        val vulnService = VulnServiceImpl(
            vulnerabilityDataService = vulnerabilityDataService,
            kevService = mockKevService,
            epssService = MockEpssService(),
            nvdRepository = MockNvdRepository(),
            riskScorer = riskScorer,
            userContextService = MockUserContextService(mockTeams = listOf("team-beta")),
            gitHubRepository = MockGitHubRepository()
        )
        val result = vulnService.fetchVulnerabilitiesForUser("test@example.com")

        assertTrue(result.teams.isEmpty())
    }

    @Test
    fun `should filter out teams with no workloads`() = runTest {
        val mockNaisApiService = MockNaisApiService(
            shouldSucceed = true,
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

        val riskScorer = no.nav.tpt.domain.risk.DefaultRiskScorer()
        val vulnerabilityDataService = no.nav.tpt.infrastructure.vulnerability.NaisApiVulnerabilityService(
            naisApiService = mockNaisApiService
        )
        val vulnService = VulnServiceImpl(
            vulnerabilityDataService = vulnerabilityDataService,
            kevService = mockKevService,
            epssService = MockEpssService(),
            nvdRepository = MockNvdRepository(),
            riskScorer = riskScorer,
            userContextService = MockUserContextService(mockTeams = listOf("team-gamma")),
            gitHubRepository = MockGitHubRepository()
        )
        val result = vulnService.fetchVulnerabilitiesForUser("test@example.com")

        assertTrue(result.teams.isEmpty())
    }

    @Test
    fun `should handle workloads without matching applications`() = runTest {
        val mockNaisApiService = MockNaisApiService(
            shouldSucceed = true,
            mockUserVulnerabilitiesData = UserVulnerabilitiesData(
                teams = listOf(
                    TeamVulnerabilitiesData(
                        teamSlug = "team-delta",
                        workloads = listOf(
                            WorkloadData(
                                id = "workload-3",
                                name = "unknown-app",
                                workloadType = "app",
                                imageTag = null,
                                repository = null,
                                environment = "production",
                                ingressTypes = emptyList(),
                                vulnerabilities = listOf(
                                    VulnerabilityData(
                                        identifier = "CVE-2023-99999",
                                        severity = "CRITICAL",
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

        val mockKevService = object : KevService {
            override suspend fun getKevCatalog() = KevCatalog(
                title = "Test KEV Catalog",
                catalogVersion = "1.0",
                dateReleased = "2023-01-01",
                count = 0,
                vulnerabilities = emptyList()
            )
        }

        val riskScorer = no.nav.tpt.domain.risk.DefaultRiskScorer()
        val vulnerabilityDataService = no.nav.tpt.infrastructure.vulnerability.NaisApiVulnerabilityService(
            naisApiService = mockNaisApiService
        )
        val vulnService = VulnServiceImpl(
            vulnerabilityDataService = vulnerabilityDataService,
            kevService = mockKevService,
            epssService = MockEpssService(),
            nvdRepository = MockNvdRepository(),
            riskScorer = riskScorer,
            userContextService = MockUserContextService(mockTeams = listOf("team-delta")),
            gitHubRepository = MockGitHubRepository()
        )
        val result = vulnService.fetchVulnerabilitiesForUser("test@example.com")

        assertEquals(1, result.teams.size)
        assertEquals(1, result.teams[0].workloads.size)
        assertEquals("unknown-app", result.teams[0].workloads[0].name)
    }

    @Test
    fun `should handle multiple teams with multiple workloads`() = runTest {
        val mockNaisApiService = MockNaisApiService(
            shouldSucceed = true,
            mockUserVulnerabilitiesData = UserVulnerabilitiesData(
                teams = listOf(
                    TeamVulnerabilitiesData(
                        teamSlug = "team-one",
                        workloads = listOf(
                            WorkloadData(
                                id = "workload-4",
                                name = "app-a",
                                workloadType = "app",
                                imageTag = null,
                                repository = null,
                                environment = "prod",
                                ingressTypes = listOf("EXTERNAL"),
                                vulnerabilities = listOf(
                                    VulnerabilityData(
                                        identifier = "CVE-2023-11111",
                                        severity = "LOW",
                                        packageName = null,
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
                                id = "workload-5",
                                name = "app-b",
                                workloadType = "app",
                                imageTag = null,
                                repository = null,
                                environment = "prod",
                                ingressTypes = listOf("INTERNAL"),
                                vulnerabilities = listOf(
                                    VulnerabilityData(
                                        identifier = "CVE-2023-22222",
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

        val riskScorer = no.nav.tpt.domain.risk.DefaultRiskScorer()
        val vulnerabilityDataService = no.nav.tpt.infrastructure.vulnerability.NaisApiVulnerabilityService(
            naisApiService = mockNaisApiService
        )
        val vulnService = VulnServiceImpl(
            vulnerabilityDataService = vulnerabilityDataService,
            kevService = mockKevService,
            epssService = MockEpssService(),
            nvdRepository = MockNvdRepository(),
            riskScorer = riskScorer,
            userContextService = MockUserContextService(mockTeams = listOf("team-one", "team-two")),
            gitHubRepository = MockGitHubRepository()
        )
        val result = vulnService.fetchVulnerabilitiesForUser("test@example.com")

        assertEquals(2, result.teams.size)

        val teamOne = result.teams.find { it.team == "team-one" }
        assertNotNull(teamOne)
        assertEquals(1, teamOne.workloads.size)
        assertEquals(1, teamOne.workloads[0].vulnerabilities.size)

        val teamTwo = result.teams.find { it.team == "team-two" }
        assertNotNull(teamTwo)
        assertEquals(1, teamTwo.workloads.size)
        assertEquals(1, teamTwo.workloads[0].vulnerabilities.size)
    }

    @Test
    fun `should return empty response when no vulnerabilities exist`() = runTest {
        val mockNaisApiService = MockNaisApiService(
            shouldSucceed = true,
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

        val riskScorer = no.nav.tpt.domain.risk.DefaultRiskScorer()
        val vulnerabilityDataService = no.nav.tpt.infrastructure.vulnerability.NaisApiVulnerabilityService(
            naisApiService = mockNaisApiService
        )
        val vulnService = VulnServiceImpl(
            vulnerabilityDataService = vulnerabilityDataService,
            kevService = mockKevService,
            epssService = MockEpssService(),
            nvdRepository = MockNvdRepository(),
            riskScorer = riskScorer,
            userContextService = MockUserContextService(mockTeams = emptyList()),
            gitHubRepository = MockGitHubRepository()
        )
        val result = vulnService.fetchVulnerabilitiesForUser("test@example.com")

        assertEquals(0, result.teams.size)
    }

    @Test
    fun `should fetch GitHub repositories for user teams`() = runTest {
        val mockGitHubRepository = MockGitHubRepository(
            mockRepositories = listOf(
                no.nav.tpt.infrastructure.github.GitHubRepositoryData(
                    nameWithOwner = "navikt/test-repo",
                    naisTeams = listOf("team-alpha"),
                    createdAt = java.time.Instant.now(),
                    updatedAt = java.time.Instant.now()
                )
            ),
            mockVulnerabilities = mapOf(
                "navikt/test-repo" to listOf(
                    no.nav.tpt.infrastructure.github.GitHubVulnerabilityData(
                        id = 1,
                        nameWithOwner = "navikt/test-repo",
                        severity = "HIGH",
                        identifiers = listOf(
                            no.nav.tpt.infrastructure.github.GitHubIdentifierData(
                                value = "CVE-2024-12345",
                                type = "CVE"
                            )
                        ),
                        createdAt = java.time.Instant.now(),
                        updatedAt = java.time.Instant.now()
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

        val riskScorer = no.nav.tpt.domain.risk.DefaultRiskScorer()
        val mockNaisApiService = MockNaisApiService(shouldSucceed = true)
        val vulnerabilityDataService = no.nav.tpt.infrastructure.vulnerability.NaisApiVulnerabilityService(
            naisApiService = mockNaisApiService
        )
        val vulnService = VulnServiceImpl(
            vulnerabilityDataService = vulnerabilityDataService,
            kevService = mockKevService,
            epssService = MockEpssService(),
            nvdRepository = MockNvdRepository(),
            riskScorer = riskScorer,
            userContextService = MockUserContextService(mockTeams = listOf("team-alpha")),
            gitHubRepository = mockGitHubRepository
        )

        val result = vulnService.fetchGitHubVulnerabilitiesForUser("test@example.com")

        assertEquals(1, result.teams.size)
        assertEquals("team-alpha", result.teams[0].team)
        assertEquals(1, result.teams[0].repositories.size)
        assertEquals("navikt/test-repo", result.teams[0].repositories[0].nameWithOwner)
        assertEquals(1, result.teams[0].repositories[0].vulnerabilities.size)
        assertEquals("CVE-2024-12345", result.teams[0].repositories[0].vulnerabilities[0].identifier)
    }

    @Test
    fun `should filter GitHub repositories by user teams`() = runTest {
        val mockGitHubRepository = MockGitHubRepository(
            mockRepositories = listOf(
                no.nav.tpt.infrastructure.github.GitHubRepositoryData(
                    nameWithOwner = "navikt/team-alpha-repo",
                    naisTeams = listOf("team-alpha"),
                    createdAt = java.time.Instant.now(),
                    updatedAt = java.time.Instant.now()
                ),
                no.nav.tpt.infrastructure.github.GitHubRepositoryData(
                    nameWithOwner = "navikt/team-beta-repo",
                    naisTeams = listOf("team-beta"),
                    createdAt = java.time.Instant.now(),
                    updatedAt = java.time.Instant.now()
                )
            ),
            mockVulnerabilities = mapOf(
                "navikt/team-alpha-repo" to listOf(
                    no.nav.tpt.infrastructure.github.GitHubVulnerabilityData(
                        id = 1,
                        nameWithOwner = "navikt/team-alpha-repo",
                        severity = "MEDIUM",
                        identifiers = listOf(
                            no.nav.tpt.infrastructure.github.GitHubIdentifierData(
                                value = "CVE-2024-11111",
                                type = "CVE"
                            )
                        ),
                        createdAt = java.time.Instant.now(),
                        updatedAt = java.time.Instant.now()
                    )
                ),
                "navikt/team-beta-repo" to listOf(
                    no.nav.tpt.infrastructure.github.GitHubVulnerabilityData(
                        id = 2,
                        nameWithOwner = "navikt/team-beta-repo",
                        severity = "HIGH",
                        identifiers = listOf(
                            no.nav.tpt.infrastructure.github.GitHubIdentifierData(
                                value = "CVE-2024-22222",
                                type = "CVE"
                            )
                        ),
                        createdAt = java.time.Instant.now(),
                        updatedAt = java.time.Instant.now()
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

        val riskScorer = no.nav.tpt.domain.risk.DefaultRiskScorer()
        val mockNaisApiService = MockNaisApiService(shouldSucceed = true)
        val vulnerabilityDataService = no.nav.tpt.infrastructure.vulnerability.NaisApiVulnerabilityService(
            naisApiService = mockNaisApiService
        )
        val vulnService = VulnServiceImpl(
            vulnerabilityDataService = vulnerabilityDataService,
            kevService = mockKevService,
            epssService = MockEpssService(),
            nvdRepository = MockNvdRepository(),
            riskScorer = riskScorer,
            userContextService = MockUserContextService(mockTeams = listOf("team-alpha")),
            gitHubRepository = mockGitHubRepository
        )

        val result = vulnService.fetchGitHubVulnerabilitiesForUser("test@example.com")

        assertEquals(1, result.teams.size)
        assertEquals("team-alpha", result.teams[0].team)
        assertEquals(1, result.teams[0].repositories.size)
        assertEquals("navikt/team-alpha-repo", result.teams[0].repositories[0].nameWithOwner)
    }

    @Test
    fun `should handle repositories with multiple teams`() = runTest {
        val mockGitHubRepository = MockGitHubRepository(
            mockRepositories = listOf(
                no.nav.tpt.infrastructure.github.GitHubRepositoryData(
                    nameWithOwner = "navikt/shared-repo",
                    naisTeams = listOf("team-alpha", "team-beta"),
                    createdAt = java.time.Instant.now(),
                    updatedAt = java.time.Instant.now()
                )
            ),
            mockVulnerabilities = mapOf(
                "navikt/shared-repo" to listOf(
                    no.nav.tpt.infrastructure.github.GitHubVulnerabilityData(
                        id = 1,
                        nameWithOwner = "navikt/shared-repo",
                        severity = "CRITICAL",
                        identifiers = listOf(
                            no.nav.tpt.infrastructure.github.GitHubIdentifierData(
                                value = "CVE-2024-99999",
                                type = "CVE"
                            )
                        ),
                        createdAt = java.time.Instant.now(),
                        updatedAt = java.time.Instant.now()
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

        val riskScorer = no.nav.tpt.domain.risk.DefaultRiskScorer()
        val mockNaisApiService = MockNaisApiService(shouldSucceed = true)
        val vulnerabilityDataService = no.nav.tpt.infrastructure.vulnerability.NaisApiVulnerabilityService(
            naisApiService = mockNaisApiService
        )
        val vulnService = VulnServiceImpl(
            vulnerabilityDataService = vulnerabilityDataService,
            kevService = mockKevService,
            epssService = MockEpssService(),
            nvdRepository = MockNvdRepository(),
            riskScorer = riskScorer,
            userContextService = MockUserContextService(mockTeams = listOf("team-alpha", "team-beta")),
            gitHubRepository = mockGitHubRepository
        )

        val result = vulnService.fetchGitHubVulnerabilitiesForUser("test@example.com")

        assertEquals(2, result.teams.size)
        val teamAlpha = result.teams.find { it.team == "team-alpha" }
        val teamBeta = result.teams.find { it.team == "team-beta" }

        assertNotNull(teamAlpha)
        assertNotNull(teamBeta)
        assertEquals(1, teamAlpha.repositories.size)
        assertEquals(1, teamBeta.repositories.size)
        assertEquals("navikt/shared-repo", teamAlpha.repositories[0].nameWithOwner)
        assertEquals("navikt/shared-repo", teamBeta.repositories[0].nameWithOwner)
    }

    @Test
    fun `should filter out non-CVE identifiers from GitHub vulnerabilities`() = runTest {
        val mockGitHubRepository = MockGitHubRepository(
            mockRepositories = listOf(
                no.nav.tpt.infrastructure.github.GitHubRepositoryData(
                    nameWithOwner = "navikt/test-repo",
                    naisTeams = listOf("team-alpha"),
                    createdAt = java.time.Instant.now(),
                    updatedAt = java.time.Instant.now()
                )
            ),
            mockVulnerabilities = mapOf(
                "navikt/test-repo" to listOf(
                    no.nav.tpt.infrastructure.github.GitHubVulnerabilityData(
                        id = 1,
                        nameWithOwner = "navikt/test-repo",
                        severity = "HIGH",
                        identifiers = listOf(
                            no.nav.tpt.infrastructure.github.GitHubIdentifierData(
                                value = "GHSA-1234-5678-9abc",
                                type = "GHSA"
                            )
                        ),
                        createdAt = java.time.Instant.now(),
                        updatedAt = java.time.Instant.now()
                    ),
                    no.nav.tpt.infrastructure.github.GitHubVulnerabilityData(
                        id = 2,
                        nameWithOwner = "navikt/test-repo",
                        severity = "MEDIUM",
                        identifiers = listOf(
                            no.nav.tpt.infrastructure.github.GitHubIdentifierData(
                                value = "CVE-2024-55555",
                                type = "CVE"
                            )
                        ),
                        createdAt = java.time.Instant.now(),
                        updatedAt = java.time.Instant.now()
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

        val riskScorer = no.nav.tpt.domain.risk.DefaultRiskScorer()
        val mockNaisApiService = MockNaisApiService(shouldSucceed = true)
        val vulnerabilityDataService = no.nav.tpt.infrastructure.vulnerability.NaisApiVulnerabilityService(
            naisApiService = mockNaisApiService
        )
        val vulnService = VulnServiceImpl(
            vulnerabilityDataService = vulnerabilityDataService,
            kevService = mockKevService,
            epssService = MockEpssService(),
            nvdRepository = MockNvdRepository(),
            riskScorer = riskScorer,
            userContextService = MockUserContextService(mockTeams = listOf("team-alpha")),
            gitHubRepository = mockGitHubRepository
        )

        val result = vulnService.fetchGitHubVulnerabilitiesForUser("test@example.com")

        assertEquals(1, result.teams.size)
        assertEquals(1, result.teams[0].repositories.size)
        assertEquals(1, result.teams[0].repositories[0].vulnerabilities.size)
        assertEquals("CVE-2024-55555", result.teams[0].repositories[0].vulnerabilities[0].identifier)
    }

    @Test
    fun `should return empty response when user has no GitHub repositories`() = runTest {
        val mockGitHubRepository = MockGitHubRepository()

        val mockKevService = object : KevService {
            override suspend fun getKevCatalog() = KevCatalog(
                title = "Test KEV Catalog",
                catalogVersion = "1.0",
                dateReleased = "2023-01-01",
                count = 0,
                vulnerabilities = emptyList()
            )
        }

        val riskScorer = no.nav.tpt.domain.risk.DefaultRiskScorer()
        val mockNaisApiService = MockNaisApiService(shouldSucceed = true)
        val vulnerabilityDataService = no.nav.tpt.infrastructure.vulnerability.NaisApiVulnerabilityService(
            naisApiService = mockNaisApiService
        )
        val vulnService = VulnServiceImpl(
            vulnerabilityDataService = vulnerabilityDataService,
            kevService = mockKevService,
            epssService = MockEpssService(),
            nvdRepository = MockNvdRepository(),
            riskScorer = riskScorer,
            userContextService = MockUserContextService(mockTeams = listOf("team-alpha")),
            gitHubRepository = mockGitHubRepository
        )

        val result = vulnService.fetchGitHubVulnerabilitiesForUser("test@example.com")

        assertEquals(0, result.teams.size)
    }

    @Test
    fun `should calculate risk scores for GitHub vulnerabilities using enrichment data`() = runTest {
        val mockGitHubRepository = MockGitHubRepository(
            mockRepositories = listOf(
                no.nav.tpt.infrastructure.github.GitHubRepositoryData(
                    nameWithOwner = "navikt/test-repo",
                    naisTeams = listOf("team-alpha"),
                    createdAt = java.time.Instant.now(),
                    updatedAt = java.time.Instant.now()
                )
            ),
            mockVulnerabilities = mapOf(
                "navikt/test-repo" to listOf(
                    no.nav.tpt.infrastructure.github.GitHubVulnerabilityData(
                        id = 1,
                        nameWithOwner = "navikt/test-repo",
                        severity = "CRITICAL",
                        identifiers = listOf(
                            no.nav.tpt.infrastructure.github.GitHubIdentifierData(
                                value = "CVE-2024-88888",
                                type = "CVE"
                            )
                        ),
                        createdAt = java.time.Instant.now(),
                        updatedAt = java.time.Instant.now()
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
                        cveID = "CVE-2024-88888",
                        vendorProject = "Test Vendor",
                        product = "Test Product",
                        vulnerabilityName = "Test Vulnerability",
                        dateAdded = "2023-01-01",
                        shortDescription = "Test description",
                        requiredAction = "Test action",
                        dueDate = "2023-12-31",
                        knownRansomwareCampaignUse = "Known",
                        notes = "Test notes",
                        cwes = emptyList()
                    )
                )
            )
        }

        val riskScorer = no.nav.tpt.domain.risk.DefaultRiskScorer()
        val mockNaisApiService = MockNaisApiService(shouldSucceed = true)
        val vulnerabilityDataService = no.nav.tpt.infrastructure.vulnerability.NaisApiVulnerabilityService(
            naisApiService = mockNaisApiService
        )
        val vulnService = VulnServiceImpl(
            vulnerabilityDataService = vulnerabilityDataService,
            kevService = mockKevService,
            epssService = MockEpssService(),
            nvdRepository = MockNvdRepository(),
            riskScorer = riskScorer,
            userContextService = MockUserContextService(mockTeams = listOf("team-alpha")),
            gitHubRepository = mockGitHubRepository
        )

        val result = vulnService.fetchGitHubVulnerabilitiesForUser("test@example.com")

        assertEquals(1, result.teams.size)
        assertEquals(1, result.teams[0].repositories[0].vulnerabilities.size)
        val vuln = result.teams[0].repositories[0].vulnerabilities[0]
        assertTrue(vuln.riskScore > 0, "Risk score should be calculated")
        assertNotNull(vuln.riskScoreBreakdown, "Risk score breakdown should be present")
    }
}
