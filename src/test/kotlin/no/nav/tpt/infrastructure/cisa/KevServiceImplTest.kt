package no.nav.tpt.infrastructure.cisa

import kotlinx.coroutines.test.runTest
import kotlin.test.*

class KevServiceImplTest {

    private class InMemoryKevRepository : KevRepository {
        private var catalog: KevCatalog? = null
        private var stale: Boolean = true
        val upsertedCatalogs = mutableListOf<KevCatalog>()

        override suspend fun getKevCatalog(): KevCatalog? = catalog

        override suspend fun getKevForCve(cveId: String): KevVulnerability? {
            return catalog?.vulnerabilities?.firstOrNull { it.cveID == cveId }
        }

        override suspend fun upsertKevCatalog(catalog: KevCatalog) {
            this.catalog = catalog
            this.stale = false
            upsertedCatalogs.add(catalog)
        }

        override suspend fun isCatalogStale(staleThresholdHours: Int): Boolean = stale

        override suspend fun getLastUpdated() = null

        fun setStale(stale: Boolean) {
            this.stale = stale
        }
    }

    private class MockKevClient(
        private val mockCatalog: KevCatalog? = null,
        private val shouldFail: Boolean = false
    ) : KevService {
        var fetchCount = 0

        override suspend fun getKevCatalog(): KevCatalog {
            fetchCount++
            if (shouldFail) {
                throw RuntimeException("API error")
            }
            return mockCatalog ?: createDefaultCatalog()
        }

        companion object {
            fun createDefaultCatalog(): KevCatalog {
                return KevCatalog(
                    title = "CISA Catalog of Known Exploited Vulnerabilities",
                    catalogVersion = "2024.01.26",
                    dateReleased = "2024-01-26",
                    count = 2,
                    vulnerabilities = listOf(
                        KevVulnerability(
                            cveID = "CVE-2021-44228",
                            vendorProject = "Apache",
                            product = "Log4j2",
                            vulnerabilityName = "Log4j2 RCE",
                            dateAdded = "2021-12-10",
                            shortDescription = "Log4j2 JNDI features vulnerability",
                            requiredAction = "Apply updates",
                            dueDate = "2021-12-24",
                            knownRansomwareCampaignUse = "Known",
                            notes = "",
                            cwes = listOf("CWE-502")
                        ),
                        KevVulnerability(
                            cveID = "CVE-2022-22965",
                            vendorProject = "VMware",
                            product = "Spring Framework",
                            vulnerabilityName = "Spring4Shell",
                            dateAdded = "2022-04-01",
                            shortDescription = "Spring Framework RCE",
                            requiredAction = "Apply updates",
                            dueDate = "2022-04-21",
                            knownRansomwareCampaignUse = "Unknown",
                            notes = "",
                            cwes = listOf("CWE-94")
                        )
                    )
                )
            }
        }
    }

    @Test
    fun `should fetch from database when catalog is fresh`() = runTest {
        val mockClient = MockKevClient()
        val repository = InMemoryKevRepository()
        repository.upsertKevCatalog(MockKevClient.createDefaultCatalog())
        repository.setStale(false)

        val service = KevServiceImpl(mockClient, repository)

        val result = service.getKevCatalog()

        assertEquals(2, result.vulnerabilities.size)
        assertEquals(0, mockClient.fetchCount)
    }

    @Test
    fun `should fetch fresh catalog when stale`() = runTest {
        val mockClient = MockKevClient()
        val repository = InMemoryKevRepository()
        repository.setStale(true)

        val service = KevServiceImpl(mockClient, repository)

        val result = service.getKevCatalog()

        assertEquals(2, result.vulnerabilities.size)
        assertEquals(1, mockClient.fetchCount)
        assertEquals(1, repository.upsertedCatalogs.size)
    }

    @Test
    fun `should fetch fresh catalog when missing`() = runTest {
        val mockClient = MockKevClient()
        val repository = InMemoryKevRepository()

        val service = KevServiceImpl(mockClient, repository)

        val result = service.getKevCatalog()

        assertEquals(2, result.vulnerabilities.size)
        assertEquals(1, mockClient.fetchCount)
        assertEquals(1, repository.upsertedCatalogs.size)
    }

    @Test
    fun `should update database after fetching fresh catalog`() = runTest {
        val mockClient = MockKevClient()
        val repository = InMemoryKevRepository()
        repository.setStale(true)

        val service = KevServiceImpl(mockClient, repository)

        service.getKevCatalog()

        assertEquals(1, repository.upsertedCatalogs.size)
        assertEquals("2024.01.26", repository.upsertedCatalogs[0].catalogVersion)
    }

    @Test
    fun `should return stale catalog on API failure`() = runTest {
        val mockClient = MockKevClient(shouldFail = true)
        val repository = InMemoryKevRepository()
        val staleCatalog = MockKevClient.createDefaultCatalog()
        repository.upsertKevCatalog(staleCatalog)
        repository.setStale(true)

        val service = KevServiceImpl(mockClient, repository)

        val result = service.getKevCatalog()

        assertEquals(2, result.vulnerabilities.size)
        assertEquals(1, mockClient.fetchCount)
    }

    @Test
    fun `should return empty catalog when API fails and no stale catalog exists`() = runTest {
        val mockClient = MockKevClient(shouldFail = true)
        val repository = InMemoryKevRepository()
        repository.setStale(true)

        val service = KevServiceImpl(mockClient, repository)

        val result = service.getKevCatalog()

        assertEquals(0, result.vulnerabilities.size)
        assertEquals("unavailable", result.catalogVersion)
        assertEquals(1, mockClient.fetchCount)
    }

    @Test
    fun `should find vulnerability by CVE ID`() = runTest {
        val mockClient = MockKevClient()
        val repository = InMemoryKevRepository()
        repository.upsertKevCatalog(MockKevClient.createDefaultCatalog())
        repository.setStale(false)

        val service = KevServiceImpl(mockClient, repository)

        val result = service.getKevForCve("CVE-2021-44228")

        assertNotNull(result)
        assertEquals("CVE-2021-44228", result.cveID)
        assertEquals("Apache", result.vendorProject)
        assertEquals("Log4j2", result.product)
    }

    @Test
    fun `should return null for non-existent CVE`() = runTest {
        val mockClient = MockKevClient()
        val repository = InMemoryKevRepository()
        repository.upsertKevCatalog(MockKevClient.createDefaultCatalog())
        repository.setStale(false)

        val service = KevServiceImpl(mockClient, repository)

        val result = service.getKevForCve("CVE-9999-99999")

        assertNull(result)
    }

    @Test
    fun `should fetch fresh catalog if stale when looking up CVE`() = runTest {
        val mockClient = MockKevClient()
        val repository = InMemoryKevRepository()
        repository.setStale(true)

        val service = KevServiceImpl(mockClient, repository)

        val result = service.getKevForCve("CVE-2021-44228")

        assertNotNull(result)
        assertEquals(1, mockClient.fetchCount)
    }

    @Test
    fun `should handle catalog with no vulnerabilities`() = runTest {
        val emptyCatalog = KevCatalog(
            title = "CISA Catalog of Known Exploited Vulnerabilities",
            catalogVersion = "2024.01.26",
            dateReleased = "2024-01-26",
            count = 0,
            vulnerabilities = emptyList()
        )
        val mockClient = MockKevClient(mockCatalog = emptyCatalog)
        val repository = InMemoryKevRepository()
        repository.setStale(true)

        val service = KevServiceImpl(mockClient, repository)

        val result = service.getKevCatalog()

        assertEquals(0, result.vulnerabilities.size)
        assertEquals(1, repository.upsertedCatalogs.size)
    }

    @Test
    fun `should use custom stale threshold`() = runTest {
        val mockClient = MockKevClient()
        val repository = InMemoryKevRepository()
        repository.upsertKevCatalog(MockKevClient.createDefaultCatalog())
        repository.setStale(false)

        val service = KevServiceImpl(mockClient, repository, staleThresholdHours = 48)

        val result = service.getKevCatalog()

        assertEquals(2, result.vulnerabilities.size)
        assertEquals(0, mockClient.fetchCount)
    }
}
