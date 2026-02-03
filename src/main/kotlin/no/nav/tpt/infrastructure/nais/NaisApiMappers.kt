package no.nav.tpt.infrastructure.nais

internal fun WorkloadVulnerabilitiesResponse.toData(): UserVulnerabilitiesData {
    val teams = data?.user?.teams?.nodes?.map { teamNode ->
        val appWorkloads = (teamNode.team.applications?.nodes ?: emptyList()).map { workloadNode ->
            mapWorkloadNode(workloadNode, "app")
        }

        val jobWorkloads = (teamNode.team.jobs?.nodes ?: emptyList()).map { workloadNode ->
            mapWorkloadNode(workloadNode, "job")
        }

        val allWorkloads = appWorkloads + jobWorkloads

        TeamVulnerabilitiesData(
            teamSlug = teamNode.team.slug,
            workloads = allWorkloads
        )
    } ?: emptyList()

    return UserVulnerabilitiesData(teams = teams)
}

private fun mapWorkloadNode(
    workloadNode: GraphQLTypes.WorkloadNode,
    workloadType: String
): WorkloadData {
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

    return WorkloadData(
        id = workloadNode.id,
        name = workloadNode.name,
        workloadType = workloadType,
        imageTag = workloadNode.image?.tag,
        repository = workloadNode.deployments.nodes.firstOrNull()?.repository,
        environment = workloadNode.deployments.nodes.firstOrNull()?.environmentName,
        ingressTypes = workloadNode.ingresses.map { it.type },
        createdAt = workloadNode.deployments.nodes.firstOrNull()?.createdAt,
        vulnerabilities = vulnerabilities
    )
}


