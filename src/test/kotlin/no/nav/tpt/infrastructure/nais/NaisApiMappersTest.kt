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

    @Test
    fun `should mark vulnerability as suppressed when Nais suppression state is IN_TRIAGE`() {
        val result = response(
            workloadNode(image = imageWithSuppression(GraphQLTypes.Suppression(state = "IN_TRIAGE")))
        ).toData()

        assertTrue(result.teams.first().workloads.first().vulnerabilities.first().suppressed)
    }

    @Test
    fun `should not mark vulnerability as suppressed when Nais suppression is null`() {
        val result = response(workloadNode(image = imageWithSuppression(null))).toData()

        assertFalse(result.teams.first().workloads.first().vulnerabilities.first().suppressed)
    }
}
