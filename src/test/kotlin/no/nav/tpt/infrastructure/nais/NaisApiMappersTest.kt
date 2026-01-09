package no.nav.tpt.infrastructure.nais

import kotlin.test.Test
import kotlin.test.assertEquals

class NaisApiMappersTest {

    @Test
    fun `should not deduplicate vulnerabilities with same identifier but different severity for user vulnerabilities`() {
        val response = VulnerabilitiesForUserResponse(
            data = VulnerabilitiesForUserResponse.Data(
                user = VulnerabilitiesForUserResponse.User(
                    teams = VulnerabilitiesForUserResponse.Teams(
                        pageInfo = VulnerabilitiesForUserResponse.PageInfo(
                            hasNextPage = false,
                            endCursor = null
                        ),
                        nodes = listOf(
                            VulnerabilitiesForUserResponse.TeamNode(
                                team = VulnerabilitiesForUserResponse.Team(
                                    slug = "test-team",
                                    workloads = VulnerabilitiesForUserResponse.Workloads(
                                        pageInfo = VulnerabilitiesForUserResponse.PageInfo(
                                            hasNextPage = false,
                                            endCursor = null
                                        ),
                                        nodes = listOf(
                                            VulnerabilitiesForUserResponse.WorkloadNode(
                                                id = "workload-1",
                                                name = "test-workload",
                                                deployments = VulnerabilitiesForUserResponse.Deployments(nodes = emptyList()),
                                                image = VulnerabilitiesForUserResponse.Image(
                                                    name = "test-image",
                                                    tag = "1.0.0",
                                                    vulnerabilities = VulnerabilitiesForUserResponse.Vulnerabilities(
                                                        pageInfo = VulnerabilitiesForUserResponse.PageInfo(
                                                            hasNextPage = false,
                                                            endCursor = null
                                                        ),
                                                        nodes = listOf(
                                                            VulnerabilitiesForUserResponse.Vulnerability(
                                                                identifier = "CVE-2023-1234",
                                                                severity = "HIGH",
                                                                packageName = null,
                                                                description = null,
                                                                vulnerabilityDetailsLink = null,
                                                                suppression = null
                                                            ),
                                                            VulnerabilitiesForUserResponse.Vulnerability(
                                                                identifier = "CVE-2023-1234",
                                                                severity = "CRITICAL",
                                                                packageName = null,
                                                                description = null,
                                                                vulnerabilityDetailsLink = null,
                                                                suppression = null
                                                            ),
                                                            VulnerabilitiesForUserResponse.Vulnerability(
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
                                    )
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
    }
}

