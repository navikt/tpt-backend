package no.nav.tpt.infrastructure.datacollector

import de.huxhorn.sulky.ulid.ULID
import java.time.Instant
import java.time.temporal.ChronoUnit
import no.nav.tpt.infrastructure.datacollector.DataCollectorChecks.checkName
import no.nav.tpt.infrastructure.datacollector.DataCollectorChecks.id
import no.nav.tpt.infrastructure.datacollector.DataCollectorChecks.repo
import no.nav.tpt.infrastructure.datacollector.DataCollectorChecks.result
import no.nav.tpt.infrastructure.datacollector.DataCollectorChecks.updatedAt
import no.nav.tpt.infrastructure.datacollector.DatacollectorCheckFailureReasons.checkId
import no.nav.tpt.infrastructure.datacollector.DatacollectorCheckFailureReasons.reason
import org.jetbrains.exposed.v1.core.Column
import org.jetbrains.exposed.v1.core.JoinType
import org.jetbrains.exposed.v1.core.ReferenceOption.CASCADE
import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.core.dao.id.EntityID
import org.jetbrains.exposed.v1.core.dao.id.IdTable
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.javatime.timestamp
import org.jetbrains.exposed.v1.jdbc.batchInsert
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.insert
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.transactions.suspendTransaction
import org.jetbrains.exposed.v1.jdbc.transactions.transaction

object DataCollectorChecks : IdTable<String>("datacollector_checks") {
    val checkName = text("check_name")
    val repo = text("repo")
    val result = text("result")
    val updatedAt = timestamp("updated_at").default(Instant.now().truncatedTo(ChronoUnit.MILLIS))

    override val id: Column<EntityID<String>> = text("id").entityId()
}

object DatacollectorCheckFailureReasons : Table("datacollector_check_failure_reasons") {
    val reason = text("reason")
    val checkId = reference(name = "check_id", refColumn = id, onDelete = CASCADE)
}

data class CheckRecord(
    val id: ULID.Value,
    val checkName: String,
    val repo: String,
    val result: String,
    val failureReasons: List<String>,
    val updatedAt: Instant,
)

interface DatacollectorRepository {
    suspend fun insert(check: CheckRecord)
    suspend fun allForRepo(name: String): List<CheckRecord>
    suspend fun delete(id: ULID.Value)
}

class DataCollectorRepositoryImpl : DatacollectorRepository {
    constructor()

    private suspend fun <T> dbQuery(block: suspend () -> T): T =
        suspendTransaction { block() }

    override suspend fun insert(check: CheckRecord) {
        transaction {
            DataCollectorChecks.insert { stmt ->
                stmt[id] = check.id.toString()
                stmt[checkName] = check.checkName
                stmt[repo] = check.repo
                stmt[result] = check.result
                stmt[updatedAt] = check.updatedAt.truncatedTo(ChronoUnit.MILLIS)
            }

            DatacollectorCheckFailureReasons.batchInsert(check.failureReasons) { reason ->
                this[DatacollectorCheckFailureReasons.reason] = reason
                this[checkId] = check.id.toString()
            }
        }
    }

    override suspend fun allForRepo(name: String): List<CheckRecord> = dbQuery {
        val failureReasons = DataCollectorChecks.join(
            DatacollectorCheckFailureReasons,
            JoinType.LEFT,
            DataCollectorChecks.id,
            checkId
            ).selectAll()
            .where { repo eq name }
            .map { it[id].value to it[reason] }
            .groupBy { it.first }
            .mapValues { entry -> entry.value.map { it.second } }

        DataCollectorChecks
            .selectAll()
            .where { repo eq name }.map {
            CheckRecord(ULID.parseULID(it[id].toString()),
                it[checkName],
                it[repo],
                it[result],
                failureReasons[it[id].toString()] ?: emptyList(),
                it[updatedAt].truncatedTo(ChronoUnit.MILLIS))
        }
    }

    override suspend fun delete(id: ULID.Value) {
        transaction {
            DataCollectorChecks.deleteWhere { DataCollectorChecks.id eq id.toString() }
        }
    }


}