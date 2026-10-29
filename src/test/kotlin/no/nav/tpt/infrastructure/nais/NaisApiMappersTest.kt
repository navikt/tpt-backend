package no.nav.tpt.infrastructure.nais

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class NaisApiMappersTest {

    private fun workloadNode(
        id: String = "app-1",
        name: String = "test-app",
        ingresses: List<GraphQLTypes.Ingress> = emptyList(),
        environmentName: String? = "prod-gcp",
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
        image = null
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
}
