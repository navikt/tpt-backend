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

    private fun response(vararg nodes: GraphQLTypes.WorkloadNode) = WorkloadVulnerabilitiesResponse(
        data = WorkloadVulnerabilitiesResponse.Data(
            user = WorkloadVulnerabilitiesResponse.User(
                teams = WorkloadVulnerabilitiesResponse.Teams(
                    pageInfo = GraphQLTypes.PageInfo(hasNextPage = false, endCursor = null),
                    nodes = listOf(
                        WorkloadVulnerabilitiesResponse.TeamNode(
                            team = GraphQLTypes.Team(
                                slug = "test-team",
                                applications = GraphQLTypes.WorkloadConnection(
                                    pageInfo = GraphQLTypes.PageInfo(hasNextPage = false, endCursor = null),
                                    nodes = nodes.toList()
                                )
                            )
                        )
                    )
                )
            )
        )
    )

    @Test
    fun `should map EXTERNAL ingress type correctly`() {
        val result = response(
            workloadNode(ingresses = listOf(GraphQLTypes.Ingress(type = "EXTERNAL")))
        ).toData()

        assertEquals(listOf("EXTERNAL"), result.teams.first().workloads.first().ingressTypes)
    }

    @Test
    fun `should map INTERNAL ingress type correctly`() {
        val result = response(
            workloadNode(ingresses = listOf(GraphQLTypes.Ingress(type = "INTERNAL")))
        ).toData()

        assertEquals(listOf("INTERNAL"), result.teams.first().workloads.first().ingressTypes)
    }

    @Test
    fun `should map AUTHENTICATED ingress type correctly`() {
        val result = response(
            workloadNode(ingresses = listOf(GraphQLTypes.Ingress(type = "AUTHENTICATED")))
        ).toData()

        assertEquals(listOf("AUTHENTICATED"), result.teams.first().workloads.first().ingressTypes)
    }

    @Test
    fun `should map empty ingress list when no ingresses`() {
        val result = response(workloadNode(ingresses = emptyList())).toData()

        assertTrue(result.teams.first().workloads.first().ingressTypes.isEmpty())
    }

    @Test
    fun `should map all ingress types when multiple ingresses are present`() {
        val result = response(
            workloadNode(
                ingresses = listOf(
                    GraphQLTypes.Ingress(type = "INTERNAL"),
                    GraphQLTypes.Ingress(type = "EXTERNAL"),
                )
            )
        ).toData()

        val ingressTypes = result.teams.first().workloads.first().ingressTypes
        assertEquals(2, ingressTypes.size)
        assertTrue(ingressTypes.contains("INTERNAL"))
        assertTrue(ingressTypes.contains("EXTERNAL"))
    }

    @Test
    fun `should map environment name from first deployment node`() {
        val result = response(workloadNode(environmentName = "prod-gcp")).toData()

        assertEquals("prod-gcp", result.teams.first().workloads.first().environment)
    }
}
