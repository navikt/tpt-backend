package no.nav.tpt.infrastructure.nais

import kotlin.test.Test
import kotlin.test.assertEquals

class NaisApiMappersTest {

    @Test
    fun `should deduplicate vulnerabilities by identifier for team vulnerabilities`() {
        val response = VulnerabilitiesForTeamResponse(
            data = VulnerabilitiesForTeamResponse.Data(
                team = VulnerabilitiesForTeamResponse.Team(
                    workloads = VulnerabilitiesForTeamResponse.Workloads(
                        pageInfo = VulnerabilitiesForTeamResponse.PageInfo(
                            hasNextPage = false,
                            endCursor = null
                        ),
                        nodes = listOf(
                            VulnerabilitiesForTeamResponse.WorkloadNode(
                                id = "workload-1",
                                name = "test-workload",
                                deployments = VulnerabilitiesForTeamResponse.Deployments(nodes = emptyList()),
                                image = VulnerabilitiesForTeamResponse.Image(
                                    name = "test-image",
                                    tag = "1.0.0",
                                    vulnerabilities = VulnerabilitiesForTeamResponse.Vulnerabilities(
                                        pageInfo = VulnerabilitiesForTeamResponse.PageInfo(
                                            hasNextPage = false,
                                            endCursor = null
                                        ),
                                        nodes = listOf(
                                            VulnerabilitiesForTeamResponse.Vulnerability(
                                                identifier = "CVE-2023-1234",
                                                severity = "HIGH",
                                                packageName = null,
                                                suppression = null
                                            ),
                                            VulnerabilitiesForTeamResponse.Vulnerability(
                                                identifier = "CVE-2023-1234",
                                                severity = "HIGH",
                                                packageName = null,
                                                suppression = null
                                            ),
                                            VulnerabilitiesForTeamResponse.Vulnerability(
                                                identifier = "CVE-2023-5678",
                                                severity = "MEDIUM",
                                                packageName = null,
                                                suppression = null
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

        val result = response.toData("test-team")

        assertEquals(1, result.workloads.size)
        assertEquals(2, result.workloads[0].vulnerabilities.size)
        assertEquals("CVE-2023-1234", result.workloads[0].vulnerabilities[0].identifier)
        assertEquals("CVE-2023-5678", result.workloads[0].vulnerabilities[1].identifier)
    }

    @Test
    fun `should not deduplicate vulnerabilities with same identifier but different severity for user vulnerabilities`() {
        val response = VulnerabilitiesForUserResponse(
            data = VulnerabilitiesForUserResponse.Data(
                user = VulnerabilitiesForUserResponse.User(
                    teams = VulnerabilitiesForUserResponse.Teams(
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
                                                                suppression = null
                                                            ),
                                                            VulnerabilitiesForUserResponse.Vulnerability(
                                                                identifier = "CVE-2023-1234",
                                                                severity = "CRITICAL",
                                                                packageName = null,
                                                                suppression = null
                                                            ),
                                                            VulnerabilitiesForUserResponse.Vulnerability(
                                                                identifier = "CVE-2023-9999",
                                                                severity = "LOW",
                                                                packageName = null,
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

    @Test
    fun `should not deduplicate vulnerabilities with same identifier but different fields`() {
        val response = VulnerabilitiesForTeamResponse(
            data = VulnerabilitiesForTeamResponse.Data(
                team = VulnerabilitiesForTeamResponse.Team(
                    workloads = VulnerabilitiesForTeamResponse.Workloads(
                        pageInfo = VulnerabilitiesForTeamResponse.PageInfo(
                            hasNextPage = false,
                            endCursor = null
                        ),
                        nodes = listOf(
                            VulnerabilitiesForTeamResponse.WorkloadNode(
                                id = "workload-1",
                                name = "test-workload",
                                deployments = VulnerabilitiesForTeamResponse.Deployments(nodes = emptyList()),
                                image = VulnerabilitiesForTeamResponse.Image(
                                    name = "test-image",
                                    tag = "1.0.0",
                                    vulnerabilities = VulnerabilitiesForTeamResponse.Vulnerabilities(
                                        pageInfo = VulnerabilitiesForTeamResponse.PageInfo(
                                            hasNextPage = false,
                                            endCursor = null
                                        ),
                                        nodes = listOf(
                                            VulnerabilitiesForTeamResponse.Vulnerability(
                                                identifier = "CVE-2023-1234",
                                                severity = "HIGH",
                                                packageName = null,
                                                suppression = null
                                            ),
                                            VulnerabilitiesForTeamResponse.Vulnerability(
                                                identifier = "CVE-2023-1234",
                                                severity = "MEDIUM",
                                                packageName = null,
                                                suppression = VulnerabilitiesForTeamResponse.Suppression(
                                                    state = "SUPPRESSED"
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

        val result = response.toData("test-team")

        assertEquals(2, result.workloads[0].vulnerabilities.size)
        assertEquals("CVE-2023-1234", result.workloads[0].vulnerabilities[0].identifier)
        assertEquals("HIGH", result.workloads[0].vulnerabilities[0].severity)
        assertEquals(false, result.workloads[0].vulnerabilities[0].suppressed)
        assertEquals("CVE-2023-1234", result.workloads[0].vulnerabilities[1].identifier)
        assertEquals("MEDIUM", result.workloads[0].vulnerabilities[1].severity)
        assertEquals(true, result.workloads[0].vulnerabilities[1].suppressed)
    }

    @Test
    fun `should handle empty vulnerabilities list`() {
        val response = VulnerabilitiesForTeamResponse(
            data = VulnerabilitiesForTeamResponse.Data(
                team = VulnerabilitiesForTeamResponse.Team(
                    workloads = VulnerabilitiesForTeamResponse.Workloads(
                        pageInfo = VulnerabilitiesForTeamResponse.PageInfo(
                            hasNextPage = false,
                            endCursor = null
                        ),
                        nodes = listOf(
                            VulnerabilitiesForTeamResponse.WorkloadNode(
                                id = "workload-1",
                                name = "test-workload",
                                deployments = VulnerabilitiesForTeamResponse.Deployments(nodes = emptyList()),
                                image = VulnerabilitiesForTeamResponse.Image(
                                    name = "test-image",
                                    tag = "1.0.0",
                                    vulnerabilities = VulnerabilitiesForTeamResponse.Vulnerabilities(
                                        pageInfo = VulnerabilitiesForTeamResponse.PageInfo(
                                            hasNextPage = false,
                                            endCursor = null
                                        ),
                                        nodes = emptyList()
                                    )
                                )
                            )
                        )
                    )
                )
            ),
            errors = null
        )

        val result = response.toData("test-team")

        assertEquals(1, result.workloads.size)
        assertEquals(0, result.workloads[0].vulnerabilities.size)
    }

    @Test
    fun `should handle multiple workloads with duplicate vulnerabilities`() {
        val response = VulnerabilitiesForTeamResponse(
            data = VulnerabilitiesForTeamResponse.Data(
                team = VulnerabilitiesForTeamResponse.Team(
                    workloads = VulnerabilitiesForTeamResponse.Workloads(
                        pageInfo = VulnerabilitiesForTeamResponse.PageInfo(
                            hasNextPage = false,
                            endCursor = null
                        ),
                        nodes = listOf(
                            VulnerabilitiesForTeamResponse.WorkloadNode(
                                id = "workload-1",
                                name = "app-1",
                                deployments = VulnerabilitiesForTeamResponse.Deployments(nodes = emptyList()),
                                image = VulnerabilitiesForTeamResponse.Image(
                                    name = "test-image",
                                    tag = "1.0.0",
                                    vulnerabilities = VulnerabilitiesForTeamResponse.Vulnerabilities(
                                        pageInfo = VulnerabilitiesForTeamResponse.PageInfo(
                                            hasNextPage = false,
                                            endCursor = null
                                        ),
                                        nodes = listOf(
                                            VulnerabilitiesForTeamResponse.Vulnerability(
                                                identifier = "CVE-2023-1111",
                                                severity = "HIGH",
                                                packageName = null,
                                                suppression = null
                                            ),
                                            VulnerabilitiesForTeamResponse.Vulnerability(
                                                identifier = "CVE-2023-1111",
                                                severity = "HIGH",
                                                packageName = null,
                                                suppression = null
                                            )
                                        )
                                    )
                                )
                            ),
                            VulnerabilitiesForTeamResponse.WorkloadNode(
                                id = "workload-2",
                                name = "app-2",
                                deployments = VulnerabilitiesForTeamResponse.Deployments(nodes = emptyList()),
                                image = VulnerabilitiesForTeamResponse.Image(
                                    name = "test-image",
                                    tag = "2.0.0",
                                    vulnerabilities = VulnerabilitiesForTeamResponse.Vulnerabilities(
                                        pageInfo = VulnerabilitiesForTeamResponse.PageInfo(
                                            hasNextPage = false,
                                            endCursor = null
                                        ),
                                        nodes = listOf(
                                            VulnerabilitiesForTeamResponse.Vulnerability(
                                                identifier = "CVE-2023-2222",
                                                severity = "CRITICAL",
                                                packageName = null,
                                                suppression = null
                                            ),
                                            VulnerabilitiesForTeamResponse.Vulnerability(
                                                identifier = "CVE-2023-2222",
                                                severity = "CRITICAL",
                                                packageName = null,
                                                suppression = null
                                            ),
                                            VulnerabilitiesForTeamResponse.Vulnerability(
                                                identifier = "CVE-2023-3333",
                                                severity = "LOW",
                                                packageName = null,
                                                suppression = null
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

        val result = response.toData("test-team")

        assertEquals(2, result.workloads.size)
        assertEquals(1, result.workloads[0].vulnerabilities.size)
        assertEquals("CVE-2023-1111", result.workloads[0].vulnerabilities[0].identifier)
        assertEquals(2, result.workloads[1].vulnerabilities.size)
        assertEquals("CVE-2023-2222", result.workloads[1].vulnerabilities[0].identifier)
        assertEquals("CVE-2023-3333", result.workloads[1].vulnerabilities[1].identifier)
    }
}

