package no.nav.tpt.infrastructure.nais

internal fun ApplicationsForUserResponse.toData(): UserApplicationsData {
    val teams = data?.user?.teams?.nodes?.map { teamNode ->
        val applications = teamNode.team.applications.nodes.map { app ->
            ApplicationData(
                name = app.name,
                ingressTypes = app.ingresses.map { IngressType.fromString(it.type) }.distinct(),
                environment = app.deployments.nodes.firstOrNull()?.environmentName
            )
        }
        TeamApplicationsData(
            teamSlug = teamNode.team.slug,
            applications = applications
        )
    } ?: emptyList()

    return UserApplicationsData(teams = teams)
}

internal fun VulnerabilitiesForUserResponse.toData(): UserVulnerabilitiesData {
    val teams = data?.user?.teams?.nodes?.map { teamNode ->
        val workloads = teamNode.team.workloads.nodes.map { workloadNode ->
            val vulnerabilities = workloadNode.image?.vulnerabilities?.nodes?.map { vuln ->
                VulnerabilityData(
                    identifier = vuln.identifier,
                    severity = vuln.severity,
                    packageName = vuln.packageName,
                    description = vuln.description,
                    vulnerabilityDetailsLink = vuln.vulnerabilityDetailsLink,
                    suppressed = vuln.suppression?.state == "SUPPRESSED"
                )
            }?.distinct() ?: emptyList()

            WorkloadData(
                id = workloadNode.id,
                name = workloadNode.name,
                imageTag = workloadNode.image?.tag,
                repository = workloadNode.deployments.nodes.firstOrNull()?.repository,
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

