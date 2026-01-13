package no.nav.tpt.infrastructure.cisa

class MockKevService(
    private val mockCatalog: KevCatalog? = null
) : KevService {
    override suspend fun getKevCatalog(): KevCatalog {
        return mockCatalog ?: KevCatalog(
            title = "CISA Catalog of Known Exploited Vulnerabilities",
            catalogVersion = "2026.01.13",
            dateReleased = "2026-01-13T18:00:00.0000Z",
            count = 1,
            vulnerabilities = listOf(
                KevVulnerability(
                    cveID = "CVE-2023-12345",
                    vendorProject = "Test Vendor",
                    product = "Test Product",
                    vulnerabilityName = "Remote Code Execution Vulnerability",
                    dateAdded = "2023-01-25",
                    shortDescription = "A critical vulnerability in test package allowing remote code execution",
                    requiredAction = "Apply mitigations per vendor instructions or discontinue use",
                    dueDate = "2023-02-15",
                    knownRansomwareCampaignUse = "Known",
                    notes = "Actively exploited in the wild",
                    cwes = listOf("CWE-78", "CWE-94")
                )
            )
        )
    }
}

