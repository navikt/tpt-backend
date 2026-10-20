package no.nav.tpt.infrastructure.securitystatus

import no.nav.tpt.domain.securitystatus.SecurityStatusConfig
import no.nav.tpt.domain.securitystatus.SecurityStatusEvaluator
import no.nav.tpt.domain.securitystatus.SecurityStatusResponse
import no.nav.tpt.domain.securitystatus.WorkloadRepository
import no.nav.tpt.domain.vulnerability.VulnerabilityRepository
import no.nav.tpt.infrastructure.vulnerability.StaleTeamSyncTrigger
import java.time.Duration
import java.time.Instant
import java.time.format.DateTimeFormatter

class SecurityStatusService(
    private val vulnerabilityRepository: VulnerabilityRepository,
    private val workloadRepository: WorkloadRepository,
    private val evaluator: SecurityStatusEvaluator,
    private val staleTeamSyncTrigger: StaleTeamSyncTrigger,
    private val config: SecurityStatusConfig,
) {
    suspend fun getSecurityStatus(userTeams: List<String>, requestedTeams: Set<String>?): SecurityStatusResponse {
        val now = Instant.now()
        val teams = if (requestedTeams == null) userTeams else userTeams.filter { it in requestedTeams }
        if (teams.isEmpty()) return SecurityStatusResponse(emptyList(), iso(now))

        val resolvedSince = evaluator.historyStart(now).minus(Duration.ofDays(config.trendWindowDays))
        val vulnerabilities = vulnerabilityRepository.getVulnerabilityLifecycleForTeams(teams, resolvedSince).groupBy { it.teamSlug }
        val workloads = workloadRepository.getWorkloadFactsForTeams(teams).groupBy { it.teamSlug }

        staleTeamSyncTrigger.triggerIfStale(teams, workloads.keys)

        val statuses = teams.sorted().mapNotNull { team ->
            evaluator.evaluate(team, vulnerabilities[team].orEmpty(), workloads[team].orEmpty(), now)
        }
        return SecurityStatusResponse(statuses, iso(now))
    }

    private fun iso(instant: Instant): String = DateTimeFormatter.ISO_INSTANT.format(instant)
}
