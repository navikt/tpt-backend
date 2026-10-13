package no.nav.tpt.infrastructure.securitystatus

import no.nav.tpt.domain.securitystatus.WorkloadFact
import no.nav.tpt.domain.securitystatus.WorkloadRepository
import no.nav.tpt.domain.securitystatus.WorkloadSnapshot
import java.time.Instant

class InMemoryWorkloadRepository(
    private val facts: List<WorkloadFact> = emptyList(),
) : WorkloadRepository {
    val syncedWorkloads = mutableMapOf<String, List<WorkloadSnapshot>>()

    override suspend fun syncTeamWorkloads(teamSlug: String, workloads: List<WorkloadSnapshot>, syncTime: Instant) {
        syncedWorkloads[teamSlug] = workloads
    }

    override suspend fun getWorkloadFactsForTeams(teamSlugs: List<String>): List<WorkloadFact> =
        facts.filter { it.teamSlug in teamSlugs }
}
