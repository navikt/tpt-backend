package no.nav.tpt.infrastructure.cisa

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import kotlinx.coroutines.runBlocking
import org.flywaydb.core.Flyway
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.deleteAll
import org.jetbrains.exposed.sql.transactions.transaction
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.utility.DockerImageName
import java.time.Instant
import kotlin.test.*

class KevRepositoryTest {

    private lateinit var postgresContainer: PostgreSQLContainer<*>
    private lateinit var database: Database
    private lateinit var repository: KevRepository

    @Before
    fun setup() {
        postgresContainer = PostgreSQLContainer(DockerImageName.parse("postgres:17"))
            .withDatabaseName("kev_test")
            .withUsername("test")
            .withPassword("test")
        postgresContainer.start()

        val hikariConfig = HikariConfig().apply {
            jdbcUrl = postgresContainer.jdbcUrl
            username = postgresContainer.username
            password = postgresContainer.password
            driverClassName = "org.postgresql.Driver"
        }
        val dataSource = HikariDataSource(hikariConfig)

        val flyway = Flyway.configure()
            .dataSource(dataSource)
            .locations("classpath:db/migration")
            .load()
        flyway.migrate()

        database = Database.connect(dataSource)
        repository = KevRepositoryImpl(database)
    }

    @After
    fun teardown() {
        transaction(database) {
            KevVulnerabilities.deleteAll()
            KevCatalogMetadata.deleteAll()
        }
        postgresContainer.stop()
    }

    @Test
    fun `should insert new KEV catalog`() = runBlocking {
        val catalog = createTestCatalog()

        repository.upsertKevCatalog(catalog)

        val result = repository.getKevCatalog()
        assertNotNull(result)
        assertEquals("CISA Catalog of Known Exploited Vulnerabilities", result.title)
        assertEquals("2024.01.26", result.catalogVersion)
        assertEquals(2, result.vulnerabilities.size)
    }

    @Test
    fun `should retrieve vulnerability by CVE ID`() = runBlocking {
        val catalog = createTestCatalog()
        repository.upsertKevCatalog(catalog)

        val result = repository.getKevForCve("CVE-2021-44228")
        assertNotNull(result)
        assertEquals("CVE-2021-44228", result.cveID)
        assertEquals("Apache", result.vendorProject)
        assertEquals("Log4j2", result.product)
    }

    @Test
    fun `should return null for non-existent CVE`() = runBlocking {
        val catalog = createTestCatalog()
        repository.upsertKevCatalog(catalog)

        val result = repository.getKevForCve("CVE-9999-99999")
        assertNull(result)
    }

    @Test
    fun `should replace old catalog with new one`() = runBlocking {
        val oldCatalog = createTestCatalog()
        repository.upsertKevCatalog(oldCatalog)

        Thread.sleep(100)

        val newCatalog = KevCatalog(
            title = "CISA Catalog of Known Exploited Vulnerabilities",
            catalogVersion = "2024.01.27",
            dateReleased = "2024-01-27",
            count = 1,
            vulnerabilities = listOf(
                KevVulnerability(
                    cveID = "CVE-2023-00000",
                    vendorProject = "Test Vendor",
                    product = "Test Product",
                    vulnerabilityName = "Test Vulnerability",
                    dateAdded = "2024-01-27",
                    shortDescription = "Test description",
                    requiredAction = "Test action",
                    dueDate = "2024-02-27",
                    knownRansomwareCampaignUse = "Unknown",
                    notes = "",
                    cwes = listOf("CWE-79")
                )
            )
        )
        repository.upsertKevCatalog(newCatalog)

        val result = repository.getKevCatalog()
        assertNotNull(result)
        assertEquals("2024.01.27", result.catalogVersion)
        assertEquals(1, result.vulnerabilities.size)
        assertEquals("CVE-2023-00000", result.vulnerabilities[0].cveID)

        val oldCveResult = repository.getKevForCve("CVE-2021-44228")
        assertNull(oldCveResult)
    }

    @Test
    fun `should detect fresh catalog`() = runBlocking {
        val catalog = createTestCatalog()
        repository.upsertKevCatalog(catalog)

        val isStale = repository.isCatalogStale(staleThresholdHours = 24)
        assertFalse(isStale)
    }

    @Test
    fun `should detect stale catalog`() = runBlocking {
        val catalog = createTestCatalog()
        repository.upsertKevCatalog(catalog)

        val isStale = repository.isCatalogStale(staleThresholdHours = 0)
        assertTrue(isStale)
    }

    @Test
    fun `should detect missing catalog as stale`() = runBlocking {
        val isStale = repository.isCatalogStale(staleThresholdHours = 24)
        assertTrue(isStale)
    }

    @Test
    fun `should return null for missing catalog`() = runBlocking {
        val result = repository.getKevCatalog()
        assertNull(result)
    }

    @Test
    fun `should get last updated timestamp`() = runBlocking {
        val catalog = createTestCatalog()
        repository.upsertKevCatalog(catalog)

        val lastUpdated = repository.getLastUpdated()
        assertNotNull(lastUpdated)
        assertTrue(lastUpdated <= Instant.now())
    }

    @Test
    fun `should return null when no catalog exists`() = runBlocking {
        val lastUpdated = repository.getLastUpdated()
        assertNull(lastUpdated)
    }

    @Test
    fun `should handle catalog with many vulnerabilities`() = runBlocking {
        val vulnerabilities = (1..250).map { i ->
            KevVulnerability(
                cveID = "CVE-2023-${i.toString().padStart(5, '0')}",
                vendorProject = "Vendor $i",
                product = "Product $i",
                vulnerabilityName = "Vulnerability $i",
                dateAdded = "2023-01-01",
                shortDescription = "Description $i",
                requiredAction = "Action $i",
                dueDate = "2023-02-01",
                knownRansomwareCampaignUse = "Unknown",
                notes = "",
                cwes = listOf("CWE-79")
            )
        }

        val catalog = KevCatalog(
            title = "CISA Catalog of Known Exploited Vulnerabilities",
            catalogVersion = "2024.01.26",
            dateReleased = "2024-01-26",
            count = vulnerabilities.size,
            vulnerabilities = vulnerabilities
        )

        repository.upsertKevCatalog(catalog)

        val result = repository.getKevCatalog()
        assertNotNull(result)
        assertEquals(250, result.vulnerabilities.size)
    }

    @Test
    fun `should handle vulnerabilities with empty CWEs`() = runBlocking {
        val catalog = KevCatalog(
            title = "CISA Catalog of Known Exploited Vulnerabilities",
            catalogVersion = "2024.01.26",
            dateReleased = "2024-01-26",
            count = 1,
            vulnerabilities = listOf(
                KevVulnerability(
                    cveID = "CVE-2021-00000",
                    vendorProject = "Test",
                    product = "Test",
                    vulnerabilityName = "Test",
                    dateAdded = "2021-01-01",
                    shortDescription = "Test",
                    requiredAction = "Test",
                    dueDate = "2021-02-01",
                    knownRansomwareCampaignUse = "Unknown",
                    notes = "",
                    cwes = emptyList()
                )
            )
        )

        repository.upsertKevCatalog(catalog)

        val result = repository.getKevForCve("CVE-2021-00000")
        assertNotNull(result)
        assertTrue(result.cwes.isEmpty())
    }

    private fun createTestCatalog(): KevCatalog {
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
                    vulnerabilityName = "Log4j2 Remote Code Execution Vulnerability",
                    dateAdded = "2021-12-10",
                    shortDescription = "Apache Log4j2 <=2.14.1 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                    requiredAction = "Apply updates per vendor instructions.",
                    dueDate = "2021-12-24",
                    knownRansomwareCampaignUse = "Known",
                    notes = "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                    cwes = listOf("CWE-502", "CWE-400", "CWE-20")
                ),
                KevVulnerability(
                    cveID = "CVE-2022-22965",
                    vendorProject = "VMware",
                    product = "Spring Framework",
                    vulnerabilityName = "Spring4Shell Remote Code Execution Vulnerability",
                    dateAdded = "2022-04-01",
                    shortDescription = "Spring Framework RCE via Data Binding on JDK 9+",
                    requiredAction = "Apply updates per vendor instructions.",
                    dueDate = "2022-04-21",
                    knownRansomwareCampaignUse = "Unknown",
                    notes = "",
                    cwes = listOf("CWE-94")
                )
            )
        )
    }
}
