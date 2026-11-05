package no.nav.tpt.infrastructure.nais

import no.nav.tpt.infrastructure.common.PurlParser

internal fun mapToUserVulnerabilitiesData(
    teamSlug: String,
    appWorkloads: List<GraphQLTypes.WorkloadNode>,
    jobWorkloads: List<GraphQLTypes.WorkloadNode>,
): UserVulnerabilitiesData {
    val workloads = appWorkloads.map { mapWorkloadNode(it, "app") } +
        jobWorkloads.map { mapWorkloadNode(it, "job") }
    return UserVulnerabilitiesData(
        teams = listOf(TeamVulnerabilitiesData(teamSlug = teamSlug, workloads = workloads))
    )
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
            packageType = PurlParser.extractPackageType(vuln.packageName),
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

