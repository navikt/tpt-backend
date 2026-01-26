package no.nav.tpt.infrastructure.epss

import kotlinx.coroutines.Dispatchers
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.transactions.experimental.newSuspendedTransaction
import org.slf4j.LoggerFactory
import java.time.Instant

class EpssRepositoryImpl(private val database: Database) : EpssRepository {
    private val logger = LoggerFactory.getLogger(EpssRepositoryImpl::class.java)

    private suspend fun <T> dbQuery(block: suspend () -> T): T =
        newSuspendedTransaction(Dispatchers.IO, database) { block() }

    override suspend fun getEpssScore(cveId: String): EpssScore? = dbQuery {
        EpssScores.selectAll().where { EpssScores.cveId eq cveId }
            .mapNotNull { toEpssScore(it) }
            .singleOrNull()
    }

    override suspend fun getEpssScores(cveIds: List<String>): Map<String, EpssScore> = dbQuery {
        if (cveIds.isEmpty()) return@dbQuery emptyMap()
        EpssScores.selectAll().where { EpssScores.cveId inList cveIds }
            .mapNotNull { toEpssScore(it) }
            .associateBy { it.cve }
    }

    override suspend fun upsertEpssScore(score: EpssScore) {
        upsertEpssScores(listOf(score))
    }

    override suspend fun upsertEpssScores(scores: List<EpssScore>) = dbQuery {
        if (scores.isEmpty()) return@dbQuery

        logger.debug("Upserting ${scores.size} EPSS scores")

        scores.chunked(100).forEach { chunk ->
            val cveIds = chunk.map { it.cve }
            val existingCveIds = EpssScores
                .select(EpssScores.cveId)
                .where { EpssScores.cveId inList cveIds }
                .map { it[EpssScores.cveId] }
                .toSet()

            val toUpdate = chunk.filter { it.cve in existingCveIds }
            val toInsert = chunk.filter { it.cve !in existingCveIds }

            toUpdate.forEach { score ->
                EpssScores.update({ EpssScores.cveId eq score.cve }) {
                    it[epssScore] = score.epss
                    it[percentile] = score.percentile
                    it[scoreDate] = score.date
                    it[lastUpdated] = Instant.now()
                    it[updatedAt] = Instant.now()
                }
            }

            if (toInsert.isNotEmpty()) {
                EpssScores.batchInsert(toInsert) { score ->
                    this[EpssScores.cveId] = score.cve
                    this[EpssScores.epssScore] = score.epss
                    this[EpssScores.percentile] = score.percentile
                    this[EpssScores.scoreDate] = score.date
                    this[EpssScores.lastUpdated] = Instant.now()
                    this[EpssScores.createdAt] = Instant.now()
                    this[EpssScores.updatedAt] = Instant.now()
                }
            }

            logger.debug("Upserted batch: ${toInsert.size} inserted, ${toUpdate.size} updated")
        }
    }

    override suspend fun getStaleCves(cveIds: List<String>, staleThresholdHours: Int): List<String> = dbQuery {
        if (cveIds.isEmpty()) return@dbQuery emptyList()

        val staleThreshold = Instant.now().minusSeconds(staleThresholdHours * 3600L)

        val existingScores = EpssScores
            .selectAll()
            .where { EpssScores.cveId inList cveIds }
            .map { it[EpssScores.cveId] to it[EpssScores.lastUpdated] }
            .toMap()

        val staleCves = cveIds.filter { cveId ->
            val lastUpdated = existingScores[cveId]
            lastUpdated == null || lastUpdated < staleThreshold
        }

        logger.debug("Found ${staleCves.size} stale/missing CVEs out of ${cveIds.size} (threshold: ${staleThresholdHours}h)")
        staleCves
    }

    private fun toEpssScore(row: ResultRow): EpssScore {
        return EpssScore(
            cve = row[EpssScores.cveId],
            epss = row[EpssScores.epssScore],
            percentile = row[EpssScores.percentile],
            date = row[EpssScores.scoreDate]
        )
    }
}
