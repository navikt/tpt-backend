package no.nav.tpt.infrastructure.epss

interface EpssRepository {
    suspend fun getEpssScore(cveId: String): EpssScore?
    suspend fun getEpssScores(cveIds: List<String>): Map<String, EpssScore>
    suspend fun upsertEpssScore(score: EpssScore)
    suspend fun upsertEpssScores(scores: List<EpssScore>)
    suspend fun getStaleCves(cveIds: List<String>, staleThresholdHours: Int = 24): List<String>
}
