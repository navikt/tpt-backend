package no.nav.tpt.infrastructure.nais

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NaisApiMappersTest {

    private fun workloadNode(
        id: String = "app-1",
        name: String = "test-app",
        ingresses: List<GraphQLTypes.Ingress> = emptyList(),
        environmentName: String? = "prod-gcp",
        image: GraphQLTypes.Image? = null,
    ) = GraphQLTypes.WorkloadNode(
        id = id,
        name = name,
        ingresses = ingresses,
        deployments = GraphQLTypes.Deployments(
            nodes = listOf(
                GraphQLTypes.Deployment(
                    repository = "navikt/test-app",
                    environmentName = environmentName,
                    createdAt = null
                )
            )
        ),
        image = image
    )

    private fun imageWithSuppression(suppression: GraphQLTypes.Suppression?) = GraphQLTypes.Image(
        name = "test-app",
        tag = "1.0.0",
        vulnerabilities = GraphQLTypes.Vulnerabilities(
            pageInfo = GraphQLTypes.PageInfo(hasNextPage = false, endCursor = null),
            nodes = listOf(
                GraphQLTypes.Vulnerability(
                    identifier = "CVE-2024-1234",
                    severity = "HIGH",
                    packageName = "pkg:maven/org.example/lib@1.0.0",
                    description = null,
                    vulnerabilityDetailsLink = null,
                    suppression = suppression
                )
            )
        )
    )

    private fun mapWorkloads(vararg nodes: GraphQLTypes.WorkloadNode) = mapToUserVulnerabilitiesData(
        teamSlug = "test-team",
        appWorkloads = nodes.toList(),
        jobWorkloads = emptyList(),
    )

    @Test
    fun `should map EXTERNAL ingress type correctly`() {
        val result = mapWorkloads(
            workloadNode(ingresses = listOf(GraphQLTypes.Ingress(type = "EXTERNAL")))
        )

        assertEquals(listOf("EXTERNAL"), result.teams.first().workloads.first().ingressTypes)
    }

    @Test
    fun `should map INTERNAL ingress type correctly`() {
        val result = mapWorkloads(
            workloadNode(ingresses = listOf(GraphQLTypes.Ingress(type = "INTERNAL")))
        )

        assertEquals(listOf("INTERNAL"), result.teams.first().workloads.first().ingressTypes)
    }

    @Test
    fun `should map AUTHENTICATED ingress type correctly`() {
        val result = mapWorkloads(
            workloadNode(ingresses = listOf(GraphQLTypes.Ingress(type = "AUTHENTICATED")))
        )

        assertEquals(listOf("AUTHENTICATED"), result.teams.first().workloads.first().ingressTypes)
    }

    @Test
    fun `should map empty ingress list when no ingresses`() {
        val result = mapWorkloads(workloadNode(ingresses = emptyList()))

        assertTrue(result.teams.first().workloads.first().ingressTypes.isEmpty())
    }

    @Test
    fun `should map all ingress types when multiple ingresses are present`() {
        val result = mapWorkloads(
            workloadNode(
                ingresses = listOf(
                    GraphQLTypes.Ingress(type = "INTERNAL"),
                    GraphQLTypes.Ingress(type = "EXTERNAL"),
                )
            )
        )

        val ingressTypes = result.teams.first().workloads.first().ingressTypes
        assertEquals(2, ingressTypes.size)
        assertTrue(ingressTypes.contains("INTERNAL"))
        assertTrue(ingressTypes.contains("EXTERNAL"))
    }

    @Test
    fun `should map environment name from first deployment node`() {
        val result = mapWorkloads(workloadNode(environmentName = "prod-gcp"))

        assertEquals("prod-gcp", result.teams.first().workloads.first().environment)
    }

    @Test
    fun `should mark vulnerability as suppressed when Nais suppression state is IN_TRIAGE`() {
        val result = mapWorkloads(
            workloadNode(image = imageWithSuppression(GraphQLTypes.Suppression(state = "IN_TRIAGE")))
        )

        assertTrue(result.teams.first().workloads.first().vulnerabilities.first().suppressed)
    }

    @Test
    fun `should not mark vulnerability as suppressed when Nais suppression is null`() {
        val result = mapWorkloads(workloadNode(image = imageWithSuppression(null)))

        assertFalse(result.teams.first().workloads.first().vulnerabilities.first().suppressed)
    }
}
