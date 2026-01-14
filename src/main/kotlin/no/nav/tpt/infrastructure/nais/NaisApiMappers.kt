package no.nav.tpt.infrastructure.nais

internal fun WorkloadVulnerabilitiesResponse.toData(): UserVulnerabilitiesData {
    val teams = data?.user?.teams?.nodes?.map { teamNode ->
        val appWorkloads = teamNode.team.applications?.nodes ?: emptyList()
        val jobWorkloads = teamNode.team.jobs?.nodes ?: emptyList()
        val allWorkloads = appWorkloads + jobWorkloads

        val workloads = allWorkloads.map { workloadNode ->
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
                environment = workloadNode.deployments.nodes.firstOrNull()?.environmentName,
                ingressTypes = workloadNode.ingresses.map { it.type },
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

