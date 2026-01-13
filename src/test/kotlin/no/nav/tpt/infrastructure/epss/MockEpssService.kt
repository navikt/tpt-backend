package no.nav.tpt.infrastructure.epss

class MockEpssService(
    private val mockScores: Map<String, EpssScore> = getDefaultMockScores()
) : EpssService {
    override suspend fun getEpssScores(cveIds: List<String>): Map<String, EpssScore> {
        return mockScores.filterKeys { it in cveIds }
    }

    companion object {
        fun getDefaultMockScores(): Map<String, EpssScore> = mapOf(
            "CVE-2023-12345" to EpssScore(cve = "CVE-2023-12345", epss = "0.85000", percentile = "0.95000", date = "2026-01-13"),
            "CVE-2023-54321" to EpssScore(cve = "CVE-2023-54321", epss = "0.42000", percentile = "0.72000", date = "2026-01-13"),
            "CVE-2024-11111" to EpssScore(cve = "CVE-2024-11111", epss = "0.15000", percentile = "0.35000", date = "2026-01-13")
        )
    }
}

