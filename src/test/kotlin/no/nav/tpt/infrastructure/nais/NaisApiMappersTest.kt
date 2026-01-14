package no.nav.tpt.infrastructure.nais

import kotlin.test.Test
import kotlin.test.assertEquals

class NaisApiMappersTest {

    @Test
    fun `should not deduplicate vulnerabilities with same identifier but different severity for user vulnerabilities`() {
        val response = WorkloadVulnerabilitiesResponse(
            data = WorkloadVulnerabilitiesResponse.Data(
                user = WorkloadVulnerabilitiesResponse.User(
                    teams = WorkloadVulnerabilitiesResponse.Teams(
                        pageInfo = WorkloadVulnerabilitiesResponse.PageInfo(
                            hasNextPage = false,
                            endCursor = null
                        ),
                        nodes = listOf(
                            WorkloadVulnerabilitiesResponse.TeamNode(
                                team = WorkloadVulnerabilitiesResponse.Team(
                                    slug = "test-team",
                                    applications = WorkloadVulnerabilitiesResponse.WorkloadConnection(
                                        pageInfo = WorkloadVulnerabilitiesResponse.PageInfo(
                                            hasNextPage = false,
                                            endCursor = null
                                        ),
                                        nodes = listOf(
                                            WorkloadVulnerabilitiesResponse.WorkloadNode(
                                                id = "workload-1",
                                                name = "test-workload",
                                                deployments = WorkloadVulnerabilitiesResponse.Deployments(
                                                    nodes = listOf(
                                                        WorkloadVulnerabilitiesResponse.Deployment(
                                                            repository = null,
                                                            environmentName = "production"
                                                        )
                                                    )
                                                ),
                                                image = WorkloadVulnerabilitiesResponse.Image(
                                                    name = "test-image",
                                                    tag = "1.0.0",
                                                    vulnerabilities = WorkloadVulnerabilitiesResponse.Vulnerabilities(
                                                        pageInfo = WorkloadVulnerabilitiesResponse.PageInfo(
                                                            hasNextPage = false,
                                                            endCursor = null
                                                        ),
                                                        nodes = listOf(
                                                            WorkloadVulnerabilitiesResponse.Vulnerability(
                                                                identifier = "CVE-2023-1234",
                                                                severity = "HIGH",
                                                                packageName = null,
                                                                description = null,
                                                                vulnerabilityDetailsLink = null,
                                                                suppression = null
                                                            ),
                                                            WorkloadVulnerabilitiesResponse.Vulnerability(
                                                                identifier = "CVE-2023-1234",
                                                                severity = "CRITICAL",
                                                                packageName = null,
                                                                description = null,
                                                                vulnerabilityDetailsLink = null,
                                                                suppression = null
                                                            ),
                                                            WorkloadVulnerabilitiesResponse.Vulnerability(
                                                                identifier = "CVE-2023-9999",
                                                                severity = "LOW",
                                                                packageName = null,
                                                                description = null,
                                                                vulnerabilityDetailsLink = null,
                                                                suppression = null
                                                            )
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    ),
                                    jobs = null
                                )
                            )
                        )
                    )
                )
            ),
            errors = null
        )

        val result = response.toData()

        assertEquals(1, result.teams.size)
        assertEquals(1, result.teams[0].workloads.size)
        assertEquals(3, result.teams[0].workloads[0].vulnerabilities.size)
        assertEquals("CVE-2023-1234", result.teams[0].workloads[0].vulnerabilities[0].identifier)
        assertEquals("HIGH", result.teams[0].workloads[0].vulnerabilities[0].severity)
        assertEquals("CVE-2023-1234", result.teams[0].workloads[0].vulnerabilities[1].identifier)
        assertEquals("CRITICAL", result.teams[0].workloads[0].vulnerabilities[1].severity)
        assertEquals("CVE-2023-9999", result.teams[0].workloads[0].vulnerabilities[2].identifier)
        assertEquals("production", result.teams[0].workloads[0].environment)
    }
}

