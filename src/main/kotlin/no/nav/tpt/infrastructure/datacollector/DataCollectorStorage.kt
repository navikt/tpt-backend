package no.nav.tpt.infrastructure.datacollector

import de.huxhorn.sulky.ulid.ULID
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.time.toJavaInstant
import kotlin.time.toKotlinInstant
import no.nav.tpt.infrastructure.datacollector.CheckResult.AllGood
import no.nav.tpt.infrastructure.datacollector.CheckResult.NeedsWork
import no.nav.tpt.infrastructure.datacollector.DataCollectorChecks.checkName
import no.nav.tpt.infrastructure.datacollector.DataCollectorChecks.description
import no.nav.tpt.infrastructure.datacollector.DataCollectorChecks.id
import no.nav.tpt.infrastructure.datacollector.DataCollectorChecks.repo
import no.nav.tpt.infrastructure.datacollector.DataCollectorChecks.result
import no.nav.tpt.infrastructure.datacollector.DataCollectorChecks.severity
import no.nav.tpt.infrastructure.datacollector.DataCollectorChecks.updatedAt
import no.nav.tpt.infrastructure.datacollector.DatacollectorCheckFailureReasons.checkId
import no.nav.tpt.infrastructure.datacollector.DatacollectorRepoOwners.owner
import org.jetbrains.exposed.v1.core.Column
import org.jetbrains.exposed.v1.core.ReferenceOption.CASCADE
import org.jetbrains.exposed.v1.core.ResultRow
import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.core.dao.id.EntityID
import org.jetbrains.exposed.v1.core.dao.id.IdTable
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.core.inList
import org.jetbrains.exposed.v1.javatime.timestamp
import org.jetbrains.exposed.v1.jdbc.Database
import org.jetbrains.exposed.v1.jdbc.batchInsert
import org.jetbrains.exposed.v1.jdbc.deleteWhere
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.transactions.suspendTransaction
import org.jetbrains.exposed.v1.jdbc.transactions.transaction

private val ulid = ULID()

object DataCollectorChecks : IdTable<String>("datacollector_checks") {
    val checkName = text("check_name")
    val description = text("description")
    val severity = text("severity").nullable()
    val repo = text("repo")
    val result = text("result")
    val updatedAt = timestamp("updated_at").default(Instant.now().truncatedTo(ChronoUnit.MILLIS))

    init {
        uniqueIndex(repo, checkName)
    }

    override val id: Column<EntityID<String>> = text("id").entityId()
}

object DatacollectorCheckFailureReasons : Table("datacollector_check_failure_reasons") {
    val reason = text("reason")
    val checkId = reference(name = "check_id", refColumn = DataCollectorChecks.id, onDelete = CASCADE)
}

object DatacollectorRepoOwners : Table("datacollector_repo_owners") {
    val owner = text("owner")
    val checkId = reference(name = "check_id", refColumn = id, onDelete = CASCADE)

    init {
        uniqueIndex(owner, checkId)
    }
}

interface DatacollectorRepository {
    suspend fun insert(checks: CheckResultsForRepo)
    suspend fun allForOwner(teamSlugs: List<String>): Map<String, List<CheckResult>>
}

class DataCollectorRepositoryImpl(private val database: Database) : DatacollectorRepository {
    private suspend fun <T> dbQuery(block: suspend () -> T): T =
        suspendTransaction(db = database) { block() }

    override suspend fun insert(checks: CheckResultsForRepo) {
        transaction {
            checks.results.forEach { check ->
                val existingIds = DataCollectorChecks.selectAll().where {
                    repo eq checks.repoName and(checkName eq check.name)
                }.map { row ->
                    row[DataCollectorChecks.id].value
                }

                if (existingIds.isNotEmpty()) {
                    DataCollectorChecks.deleteWhere { id inList existingIds }
                }
            }

            val insertedChecks = DataCollectorChecks.batchInsert(
                data = checks.results
            ) { checkResult ->
                val rowId = ulid.nextValue()
                this[DataCollectorChecks.id] = rowId.toString()
                this[checkName] = checkResult.name
                this[description] = checkResult.desc
                this[severity] = checkResult.severity.toString()
                this[repo] = checks.repoName
                this[result] = checkResult.javaClass.simpleName
                this[updatedAt] = checkResult.whenChecked.toJavaInstant().truncatedTo(ChronoUnit.MILLIS)
            }.associate { row ->
                row[checkName] to row[DataCollectorChecks.id].value
            }

            checks.results.filterIsInstance<NeedsWork>().associateBy { ulid.nextValue() }
                .forEach { (checkId, checkResult) ->
                    DatacollectorCheckFailureReasons.batchInsert(checkResult.reasons) { reason ->
                        this[DatacollectorCheckFailureReasons.reason] = reason
                        this[DatacollectorCheckFailureReasons.checkId] = insertedChecks[checkResult.name]!!
                    }
                }

            checks.results.forEach { checkResult ->
                DatacollectorRepoOwners.batchInsert(data = checks.repoOwners) { owner ->
                    this[DatacollectorRepoOwners.owner] = owner
                    this[DatacollectorRepoOwners.checkId] = insertedChecks[checkResult.name]!!
                }
            }

        }
    }

    override suspend fun allForOwner(teamSlugs: List<String>): Map<String, List<CheckResult>> = dbQuery {
        val ids =
            DatacollectorRepoOwners.selectAll().where {
                owner inList  teamSlugs
            }.map { row ->
                row[DatacollectorRepoOwners.checkId].value
            }

        val reasonRows = DatacollectorCheckFailureReasons.selectAll()
            .where { checkId inList ids }

        val reasonMapping = reasonRows
            .groupBy { it[checkId].value }
            .mapValues { it.value.extractReasons() }
            .toMap()

        DataCollectorChecks.selectAll()
            .where { id inList ids }
            .map {
                it[repo] to if (it[result] == AllGood::class.java.simpleName) {
                    AllGood(name = it[checkName], desc = it[description], severity = Severity.valueOf(it[severity] ?: "UNKNOWN"),
                        whenChecked = it[updatedAt].truncatedTo(ChronoUnit.MILLIS).toKotlinInstant())
                } else {
                    val reasons = reasonMapping.get(it[id].value) ?: emptyList()
                    NeedsWork(name = it[checkName], desc = it[description], severity = Severity.valueOf(it[severity] ?: "UNKNOWN"),
                        whenChecked = it[updatedAt].truncatedTo(ChronoUnit.MILLIS).toKotlinInstant(), reasons = reasons)
                }
            }
            .groupBy { it.first }
            .mapValues { groupedByRepo -> groupedByRepo.value.map { (_, checks) -> checks } }
    }

    private fun List<ResultRow>.extractReasons() = this.map { it[DatacollectorCheckFailureReasons.reason] }

}

