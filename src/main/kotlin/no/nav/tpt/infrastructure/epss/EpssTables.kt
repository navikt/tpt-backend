package no.nav.tpt.infrastructure.epss

import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.javatime.timestamp
import java.time.Instant

object EpssScores : Table("epss_scores") {
    val cveId = varchar("cve_id", 20)
    val epssScore = varchar("epss_score", 20)
    val percentile = varchar("percentile", 20)
    val scoreDate = varchar("score_date", 20)
    val lastUpdated = timestamp("last_updated").default(Instant.now())
    val createdAt = timestamp("created_at").default(Instant.now())
    val updatedAt = timestamp("updated_at").default(Instant.now())

    override val primaryKey = PrimaryKey(cveId)
}