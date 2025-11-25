package no.nav.tpt.infrastructure.nais

internal fun ApplicationsForTeamResponse.toData(teamSlug: String): TeamApplicationsData {
    val applications = data?.team?.applications?.nodes?.map { app ->
        ApplicationData(
            name = app.name,
            ingressTypes = app.ingresses.map { IngressType.fromString(it.type) }.distinct()
        )
    } ?: emptyList()

    return TeamApplicationsData(
        teamSlug = teamSlug,
        applications = applications
    )
}

internal fun ApplicationsForUserResponse.toData(): UserApplicationsData {
    val teams = data?.user?.teams?.nodes?.map { teamNode ->
        val applications = teamNode.team.applications.nodes.map { app ->
            ApplicationData(
                name = app.name,
                ingressTypes = app.ingresses.map { IngressType.fromString(it.type) }.distinct()
            )
        }
        TeamApplicationsData(
            teamSlug = teamNode.team.slug,
            applications = applications
        )
    } ?: emptyList()

    return UserApplicationsData(teams = teams)
}

internal fun VulnerabilitiesForTeamResponse.toData(teamSlug: String): TeamVulnerabilitiesData {
    val workloads = data?.team?.workloads?.nodes?.map { workloadNode ->
        val vulnerabilities = workloadNode.image?.vulnerabilities?.nodes?.map { vuln ->
            VulnerabilityData(
                identifier = vuln.identifier,
                severity = vuln.severity,
                suppressed = vuln.suppression?.state == "SUPPRESSED"
            )
        } ?: emptyList()

        WorkloadData(
            id = workloadNode.id,
            name = workloadNode.name,
            imageTag = workloadNode.image?.tag,
            vulnerabilities = vulnerabilities
        )
    } ?: emptyList()

    return TeamVulnerabilitiesData(
        teamSlug = teamSlug,
        workloads = workloads
    )
}

internal fun VulnerabilitiesForUserResponse.toData(): UserVulnerabilitiesData {
    val teams = data?.user?.teams?.nodes?.map { teamNode ->
        val workloads = teamNode.team.workloads.nodes.map { workloadNode ->
            val vulnerabilities = workloadNode.image?.vulnerabilities?.nodes?.map { vuln ->
                VulnerabilityData(
                    identifier = vuln.identifier,
                    severity = vuln.severity,
                    suppressed = vuln.suppression?.state == "SUPPRESSED"
                )
            } ?: emptyList()

            WorkloadData(
                id = workloadNode.id,
                name = workloadNode.name,
                imageTag = workloadNode.image?.tag,
                vulnerabilities = vulnerabilities
            )
        }

        TeamVulnerabilitiesData(
            teamSlug = teamNode.team.slug,
            workloads = workloads
        )
    } ?: emptyList()

    return UserVulnerabilitiesData(teams = teams)
}

