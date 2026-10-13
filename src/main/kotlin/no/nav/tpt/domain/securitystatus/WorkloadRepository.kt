package no.nav.tpt.domain.securitystatus

import java.time.Instant

data class WorkloadSnapshot(
    val appNaisId: String,
    val appName: String,
    val workloadType: String,
    val environment: String?,
    val deployedAt: Instant?,
)

data class WorkloadFact(
    val teamSlug: String,
    val appNaisId: String,
    val appName: String,
    val firstSeenAt: Instant,
    val removedAt: Instant?,
    val deployments: List<Instant>,
)

interface WorkloadRepository {
    suspend fun syncTeamWorkloads(teamSlug: String, workloads: List<WorkloadSnapshot>, syncTime: Instant)

    suspend fun getWorkloadFactsForTeams(teamSlugs: List<String>): List<WorkloadFact>
}
