package no.nav.tpt.infrastructure.securitystatus

import no.nav.tpt.domain.securitystatus.WorkloadAbsence
import no.nav.tpt.domain.securitystatus.WorkloadFact
import no.nav.tpt.domain.securitystatus.WorkloadRepository
import no.nav.tpt.domain.securitystatus.WorkloadSnapshot
import org.jetbrains.exposed.v1.core.and
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.core.inList
import org.jetbrains.exposed.v1.core.isNotNull
import org.jetbrains.exposed.v1.core.isNull
import org.jetbrains.exposed.v1.core.notInList
import org.jetbrains.exposed.v1.jdbc.batchInsert
import org.jetbrains.exposed.v1.jdbc.batchUpsert
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.transactions.suspendTransaction
import org.jetbrains.exposed.v1.jdbc.update
import java.time.Instant

class WorkloadRepositoryImpl : WorkloadRepository {
    private suspend fun <T> dbQuery(block: suspend () -> T): T = suspendTransaction { block() }

    override suspend fun syncTeamWorkloads(
        teamSlug: String,
        workloads: List<WorkloadSnapshot>,
        syncTime: Instant,
    ) {
        dbQuery {
            val seenIds = workloads.map { it.appNaisId }.distinct()

            if (workloads.isNotEmpty()) {
                val returning =
                    Workloads
                        .selectAll()
                        .where { (Workloads.appNaisId inList seenIds) and Workloads.removedAt.isNotNull() }
                        .map { it[Workloads.appNaisId] to it[Workloads.removedAt]!! }
                if (returning.isNotEmpty()) {
                    WorkloadAbsences.batchInsert(returning, ignore = true, shouldReturnGeneratedValues = false) { (id, removed) ->
                        this[WorkloadAbsences.appNaisId] = id
                        this[WorkloadAbsences.removedAt] = removed
                        this[WorkloadAbsences.returnedAt] = syncTime
                    }
                }

                Workloads.batchUpsert(
                    workloads.distinctBy { it.appNaisId },
                    Workloads.appNaisId,
                    onUpdateExclude = listOf(Workloads.firstSeenAt),
                    shouldReturnGeneratedValues = false,
                ) { workload ->
                    this[Workloads.appNaisId] = workload.appNaisId
                    this[Workloads.teamSlug] = teamSlug
                    this[Workloads.appName] = workload.appName
                    this[Workloads.workloadType] = workload.workloadType
                    this[Workloads.environment] = workload.environment
                    this[Workloads.firstSeenAt] = syncTime
                    this[Workloads.removedAt] = null
                }

                val deployments = workloads.distinctBy { it.appNaisId }.filter { it.deployedAt != null }
                if (deployments.isNotEmpty()) {
                    WorkloadDeployments.batchInsert(deployments, ignore = true, shouldReturnGeneratedValues = false) {
                        this[WorkloadDeployments.appNaisId] = it.appNaisId
                        this[WorkloadDeployments.deployedAt] = it.deployedAt!!
                    }
                }
            }

            Workloads.update({
                (Workloads.teamSlug eq teamSlug) and
                    (Workloads.removedAt.isNull()) and
                    (Workloads.appNaisId notInList seenIds)
            }) {
                it[removedAt] = syncTime
            }
        }
    }

    override suspend fun getWorkloadFactsForTeams(teamSlugs: List<String>): List<WorkloadFact> =
        dbQuery {
            val workloads = Workloads.selectAll().where { Workloads.teamSlug inList teamSlugs }.toList()
            val deploymentsById =
                if (workloads.isEmpty()) {
                    emptyMap()
                } else {
                    WorkloadDeployments
                        .selectAll()
                        .where { WorkloadDeployments.appNaisId inList workloads.map { it[Workloads.appNaisId] } }
                        .groupBy({ it[WorkloadDeployments.appNaisId] }, { it[WorkloadDeployments.deployedAt] })
                }

            val ids = workloads.map { it[Workloads.appNaisId] }
            val absencesById =
                if (ids.isEmpty()) {
                    emptyMap()
                } else {
                    WorkloadAbsences
                        .selectAll()
                        .where { WorkloadAbsences.appNaisId inList ids }
                        .groupBy(
                            { it[WorkloadAbsences.appNaisId] },
                            { WorkloadAbsence(it[WorkloadAbsences.removedAt], it[WorkloadAbsences.returnedAt]) },
                        )
                }

            workloads.map { row ->
                WorkloadFact(
                    teamSlug = row[Workloads.teamSlug],
                    appNaisId = row[Workloads.appNaisId],
                    appName = row[Workloads.appName],
                    firstSeenAt = row[Workloads.firstSeenAt],
                    removedAt = row[Workloads.removedAt],
                    deployments = deploymentsById[row[Workloads.appNaisId]].orEmpty(),
                    absences = absencesById[row[Workloads.appNaisId]].orEmpty(),
                )
            }
        }
}
