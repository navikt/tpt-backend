package no.nav.appsecguide.infrastructure.nais

import no.nav.appsecguide.domain.*

fun ApplicationsForTeamResponse.toDto(teamSlug: String): TeamApplicationsDto {
    val applications = data?.team?.applications?.nodes?.map { app ->
        ApplicationDto(
            name = app.name,
            ingressTypes = app.ingresses.map { it.type }.distinct()
        )
    } ?: emptyList()

    return TeamApplicationsDto(
        team = teamSlug,
        applications = applications
    )
}

fun ApplicationsForUserResponse.toDto(): UserApplicationsDto {
    val teams = data?.user?.teams?.nodes?.map { teamNode ->
        val applications = teamNode.team.applications.nodes.map { app ->
            ApplicationDto(
                name = app.name,
                ingressTypes = app.ingresses.map { it.type }.distinct()
            )
        }
        TeamApplicationsDto(
            team = teamNode.team.slug,
            applications = applications
        )
    } ?: emptyList()

    return UserApplicationsDto(teams = teams)
}

fun VulnerabilitiesForTeamResponse.toDto(teamSlug: String): TeamVulnerabilitiesDto {
    val workloads = data?.team?.workloads?.nodes?.mapNotNull { workloadNode ->
        val vulnerabilities = workloadNode.image?.vulnerabilities?.nodes?.map { vuln ->
            VulnerabilityDto(
                identifier = vuln.identifier,
                severity = vuln.severity,
                suppressed = vuln.suppression?.state == "SUPPRESSED"
            )
        } ?: emptyList()

        if (vulnerabilities.isNotEmpty()) {
            WorkloadDto(
                name = workloadNode.name,
                vulnerabilities = vulnerabilities
            )
        } else {
            null
        }
    } ?: emptyList()

    return TeamVulnerabilitiesDto(
        team = teamSlug,
        workloads = workloads
    )
}

fun VulnerabilitiesForUserResponse.toDto(): UserVulnerabilitiesDto {
    val teams = data?.user?.teams?.nodes?.mapNotNull { teamNode ->
        val workloads = teamNode.team.workloads.nodes.mapNotNull { workloadNode ->
            val vulnerabilities = workloadNode.image?.vulnerabilities?.nodes?.map { vuln ->
                VulnerabilityDto(
                    identifier = vuln.identifier,
                    severity = vuln.severity,
                    suppressed = vuln.suppression?.state == "SUPPRESSED"
                )
            } ?: emptyList()

            if (vulnerabilities.isNotEmpty()) {
                WorkloadDto(
                    name = workloadNode.name,
                    vulnerabilities = vulnerabilities
                )
            } else {
                null
            }
        }

        if (workloads.isNotEmpty()) {
            TeamVulnerabilitiesDto(
                team = teamNode.team.slug,
                workloads = workloads
            )
        } else {
            null
        }
    }?.filterNotNull() ?: emptyList()

    return UserVulnerabilitiesDto(teams = teams)
}

