package no.nav.tpt.infrastructure.vulns

import kotlinx.serialization.json.Json
import no.nav.tpt.domain.*
import no.nav.tpt.domain.risk.RiskScoreBreakdown
import no.nav.tpt.domain.risk.RiskFactorExplanation
import no.nav.tpt.domain.risk.ImpactLevel
import no.nav.tpt.domain.user.UserRole
import java.io.File

class MockVulnService : VulnService {
    private val json = Json {
        ignoreUnknownKeys = true
        isLenient = true
    }

    private val mockDataFile = File("src/test/resources/mock-vulnerabilities.json")

    private fun getDefaultMockData(): VulnResponse {
        return VulnResponse(
            userRole = UserRole.DEVELOPER,
            teams = listOf(
                VulnTeamDto(
                    team = "team-lokal-utvikler",
                    workloads = listOf(
                        VulnWorkloadDto(
                            id = "app-1",
                            name = "tpt-backend",
                            workloadType = "app",
                            environment = "prod-gcp",
                            repository = "navikt/tpt-backend",
                            lastDeploy = "2023-10-15T08:30:00.000Z",
                            vulnerabilities = listOf(
                                VulnVulnerabilityDto(
                                    identifier = "CVE-2024-12345",
                                    name = "spring-boot-starter",
                                    packageName = "pkg:maven/org.springframework.boot/spring-boot-starter@2.7.0",
                                    description = "Spring Boot vulnerability allowing remote code execution through crafted requests",
                                    vulnerabilityDetailsLink = "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
                                    riskScore = 245.0,
                                    riskScoreBreakdown = RiskScoreBreakdown(
                                        baseScore = 70.0,
                                        factors = listOf(
                                            RiskFactorExplanation(
                                                name = "severity",
                                                contribution = 70.0,
                                                explanation = "Base CVSS score: HIGH (7.0)",
                                                impact = ImpactLevel.HIGH,
                                                multiplier = 1.0
                                            ),
                                            RiskFactorExplanation(
                                                name = "exposure",
                                                contribution = 140.0,
                                                explanation = "Application is externally accessible",
                                                impact = ImpactLevel.CRITICAL,
                                                multiplier = 2.0
                                            ),
                                            RiskFactorExplanation(
                                                name = "kev",
                                                contribution = 245.0,
                                                explanation = "Listed in CISA KEV catalog",
                                                impact = ImpactLevel.CRITICAL,
                                                multiplier = 1.75
                                            )
                                        ),
                                        totalScore = 245.0
                                    )
                                ),
                                VulnVulnerabilityDto(
                                    identifier = "CVE-2024-23456",
                                    name = "log4j-core",
                                    packageName = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                                    description = "Apache Log4j2 remote code execution vulnerability",
                                    vulnerabilityDetailsLink = "https://nvd.nist.gov/vuln/detail/CVE-2024-23456",
                                    riskScore = 180.0,
                                    riskScoreBreakdown = RiskScoreBreakdown(
                                        baseScore = 90.0,
                                        factors = listOf(
                                            RiskFactorExplanation(
                                                name = "severity",
                                                contribution = 90.0,
                                                explanation = "Base CVSS score: CRITICAL (9.0)",
                                                impact = ImpactLevel.CRITICAL,
                                                multiplier = 1.0
                                            ),
                                            RiskFactorExplanation(
                                                name = "exposure",
                                                contribution = 180.0,
                                                explanation = "Application is externally accessible",
                                                impact = ImpactLevel.CRITICAL,
                                                multiplier = 2.0
                                            )
                                        ),
                                        totalScore = 180.0
                                    )
                                )
                            )
                        ),
                        VulnWorkloadDto(
                            id = "app-2",
                            name = "security-scanner",
                            workloadType = "app",
                            environment = "prod-gcp",
                            repository = "navikt/security-scanner",
                            lastDeploy = "2026-02-01T14:20:00.000Z",
                            vulnerabilities = listOf(
                                VulnVulnerabilityDto(
                                    identifier = "CVE-2025-11111",
                                    name = "netty",
                                    packageName = "pkg:maven/io.netty/netty-codec-http@4.1.90",
                                    description = "Critical HTTP request smuggling vulnerability in Netty discovered last week",
                                    vulnerabilityDetailsLink = "https://nvd.nist.gov/vuln/detail/CVE-2025-11111",
                                    riskScore = 315.0,
                                    riskScoreBreakdown = RiskScoreBreakdown(
                                        baseScore = 90.0,
                                        factors = listOf(
                                            RiskFactorExplanation(
                                                name = "severity",
                                                contribution = 90.0,
                                                explanation = "Base CVSS score: CRITICAL (9.0)",
                                                impact = ImpactLevel.CRITICAL,
                                                multiplier = 1.0
                                            ),
                                            RiskFactorExplanation(
                                                name = "exposure",
                                                contribution = 180.0,
                                                explanation = "Application is externally accessible",
                                                impact = ImpactLevel.CRITICAL,
                                                multiplier = 2.0
                                            ),
                                            RiskFactorExplanation(
                                                name = "kev",
                                                contribution = 315.0,
                                                explanation = "Listed in CISA KEV catalog",
                                                impact = ImpactLevel.CRITICAL,
                                                multiplier = 1.75
                                            )
                                        ),
                                        totalScore = 315.0
                                    )
                                ),
                                VulnVulnerabilityDto(
                                    identifier = "CVE-2025-22222",
                                    name = "spring-security",
                                    packageName = "pkg:maven/org.springframework.security/spring-security-core@5.7.0",
                                    description = "Critical authentication bypass in Spring Security from 3 days ago",
                                    vulnerabilityDetailsLink = "https://nvd.nist.gov/vuln/detail/CVE-2025-22222",
                                    riskScore = 252.0,
                                    riskScoreBreakdown = RiskScoreBreakdown(
                                        baseScore = 90.0,
                                        factors = listOf(
                                            RiskFactorExplanation(
                                                name = "severity",
                                                contribution = 90.0,
                                                explanation = "Base CVSS score: CRITICAL (9.0)",
                                                impact = ImpactLevel.CRITICAL,
                                                multiplier = 1.0
                                            ),
                                            RiskFactorExplanation(
                                                name = "exposure",
                                                contribution = 180.0,
                                                explanation = "Application is externally accessible",
                                                impact = ImpactLevel.CRITICAL,
                                                multiplier = 2.0
                                            ),
                                            RiskFactorExplanation(
                                                name = "epss",
                                                contribution = 252.0,
                                                explanation = "High exploitation probability (85%)",
                                                impact = ImpactLevel.CRITICAL,
                                                multiplier = 1.4
                                            )
                                        ),
                                        totalScore = 252.0
                                    )
                                ),
                                VulnVulnerabilityDto(
                                    identifier = "CVE-2024-34567",
                                    name = "postgres",
                                    packageName = "pkg:maven/org.postgresql/postgresql@42.3.1",
                                    description = "PostgreSQL JDBC driver SQL injection vulnerability",
                                    vulnerabilityDetailsLink = "https://nvd.nist.gov/vuln/detail/CVE-2024-34567",
                                    riskScore = 52.5,
                                    riskScoreBreakdown = RiskScoreBreakdown(
                                        baseScore = 70.0,
                                        factors = listOf(
                                            RiskFactorExplanation(
                                                name = "severity",
                                                contribution = 70.0,
                                                explanation = "Base CVSS score: HIGH (7.0)",
                                                impact = ImpactLevel.HIGH,
                                                multiplier = 1.0
                                            ),
                                            RiskFactorExplanation(
                                                name = "exposure",
                                                contribution = 52.5,
                                                explanation = "Application is only internally accessible",
                                                impact = ImpactLevel.MEDIUM,
                                                multiplier = 0.75
                                            )
                                        ),
                                        totalScore = 52.5
                                    )
                                )
                            )
                        ),
                        VulnWorkloadDto(
                            id = "app-3",
                            name = "legacy-payment-system",
                            workloadType = "app",
                            environment = "prod-gcp",
                            repository = "navikt/legacy-payment",
                            lastDeploy = "2023-08-20T10:15:00.000Z",
                            vulnerabilities = listOf(
                                VulnVulnerabilityDto(
                                    identifier = "CVE-2023-98765",
                                    name = "commons-collections",
                                    packageName = "pkg:maven/commons-collections/commons-collections@3.2.1",
                                    description = "High severity deserialization vulnerability in old Commons Collections library",
                                    vulnerabilityDetailsLink = "https://nvd.nist.gov/vuln/detail/CVE-2023-98765",
                                    riskScore = 122.5,
                                    riskScoreBreakdown = RiskScoreBreakdown(
                                        baseScore = 70.0,
                                        factors = listOf(
                                            RiskFactorExplanation(
                                                name = "severity",
                                                contribution = 70.0,
                                                explanation = "Base CVSS score: HIGH (7.0)",
                                                impact = ImpactLevel.HIGH,
                                                multiplier = 1.0
                                            ),
                                            RiskFactorExplanation(
                                                name = "exposure",
                                                contribution = 122.5,
                                                explanation = "Application is externally accessible",
                                                impact = ImpactLevel.CRITICAL,
                                                multiplier = 1.75
                                            )
                                        ),
                                        totalScore = 122.5
                                    )
                                ),
                                VulnVulnerabilityDto(
                                    identifier = "CVE-2023-87654",
                                    name = "jackson-databind",
                                    packageName = "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.0",
                                    description = "Medium severity vulnerability in outdated Jackson library",
                                    vulnerabilityDetailsLink = "https://nvd.nist.gov/vuln/detail/CVE-2023-87654",
                                    riskScore = 42.0,
                                    riskScoreBreakdown = RiskScoreBreakdown(
                                        baseScore = 60.0,
                                        factors = listOf(
                                            RiskFactorExplanation(
                                                name = "severity",
                                                contribution = 60.0,
                                                explanation = "Base CVSS score: MEDIUM (6.0)",
                                                impact = ImpactLevel.MEDIUM,
                                                multiplier = 1.0
                                            ),
                                            RiskFactorExplanation(
                                                name = "exposure",
                                                contribution = 42.0,
                                                explanation = "Application is only internally accessible",
                                                impact = ImpactLevel.MEDIUM,
                                                multiplier = 0.7
                                            )
                                        ),
                                        totalScore = 42.0
                                    )
                                )
                            )
                        )
                    )
                ),
                VulnTeamDto(
                    team = "team-b",
                    workloads = listOf(
                        VulnWorkloadDto(
                            id = "job-1",
                            name = "data-sync-job",
                            workloadType = "job",
                            environment = "prod-gcp",
                            repository = "navikt/data-sync",
                            lastDeploy = "2026-01-28T09:00:00.000Z",
                            vulnerabilities = listOf(
                                VulnVulnerabilityDto(
                                    identifier = "CVE-2025-99999",
                                    name = "kotlin-stdlib",
                                    packageName = "pkg:maven/org.jetbrains.kotlin/kotlin-stdlib@1.8.0",
                                    description = "Critical vulnerability in Kotlin standard library from yesterday",
                                    vulnerabilityDetailsLink = "https://nvd.nist.gov/vuln/detail/CVE-2025-99999",
                                    riskScore = 45.0,
                                    riskScoreBreakdown = RiskScoreBreakdown(
                                        baseScore = 90.0,
                                        factors = listOf(
                                            RiskFactorExplanation(
                                                name = "severity",
                                                contribution = 90.0,
                                                explanation = "Base CVSS score: CRITICAL (9.0)",
                                                impact = ImpactLevel.CRITICAL,
                                                multiplier = 1.0
                                            ),
                                            RiskFactorExplanation(
                                                name = "workload",
                                                contribution = 45.0,
                                                explanation = "Naisjob has reduced attack surface",
                                                impact = ImpactLevel.LOW,
                                                multiplier = 0.5
                                            )
                                        ),
                                        totalScore = 45.0
                                    )
                                ),
                                VulnVulnerabilityDto(
                                    identifier = "CVE-2024-45678",
                                    name = "jackson-databind",
                                    packageName = "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0",
                                    description = "Jackson deserialization vulnerability allowing arbitrary code execution",
                                    vulnerabilityDetailsLink = "https://nvd.nist.gov/vuln/detail/CVE-2024-45678",
                                    riskScore = 30.0,
                                    riskScoreBreakdown = RiskScoreBreakdown(
                                        baseScore = 60.0,
                                        factors = listOf(
                                            RiskFactorExplanation(
                                                name = "severity",
                                                contribution = 60.0,
                                                explanation = "Base CVSS score: MEDIUM (6.0)",
                                                impact = ImpactLevel.MEDIUM,
                                                multiplier = 1.0
                                            ),
                                            RiskFactorExplanation(
                                                name = "workload",
                                                contribution = 30.0,
                                                explanation = "Naisjob has reduced attack surface",
                                                impact = ImpactLevel.LOW,
                                                multiplier = 0.5
                                            )
                                        ),
                                        totalScore = 30.0
                                    )
                                )
                            )
                        )
                    )
                )
            )
        )
    }

    override suspend fun fetchVulnerabilitiesForUser(email: String, groups: List<String>): VulnResponse {
        if (!mockDataFile.exists()) {
            return getDefaultMockData()
        }

        return try {
            val jsonContent = mockDataFile.readText()
            if (jsonContent.isBlank()) {
                return getDefaultMockData()
            }
            val response = json.decodeFromString<VulnResponse>(jsonContent)

            // If the JSON file has no teams, return default mock data instead
            if (response.teams.isEmpty()) {
                return getDefaultMockData()
            }

            response
        } catch (e: Exception) {
            getDefaultMockData()
        }
    }

    override suspend fun fetchGitHubVulnerabilitiesForUser(email: String, groups: List<String>): GitHubVulnResponse {
        return GitHubVulnResponse(
            userRole = UserRole.DEVELOPER,
            teams = listOf(
                GitHubVulnTeamDto(
                    team = "team-lokal-utvikler",
                    repositories = listOf(
                        GitHubVulnRepositoryDto(
                            nameWithOwner = "navikt/tpt-backend",
                            vulnerabilities = listOf(
                                GitHubVulnVulnerabilityDto(
                                    identifier = "CVE-2024-98765",
                                    packageName = "lodash",
                                    packageEcosystem = "NPM",
                                    description = "GitHub-detected vulnerability in Node.js dependencies allowing prototype pollution",
                                    summary = "Prototype pollution vulnerability in lodash",
                                    vulnerabilityDetailsLink = "https://nvd.nist.gov/vuln/detail/CVE-2024-98765",
                                    riskScore = 140.0,
                                    riskScoreBreakdown = RiskScoreBreakdown(
                                        baseScore = 70.0,
                                        factors = listOf(
                                            RiskFactorExplanation(
                                                name = "severity",
                                                contribution = 70.0,
                                                explanation = "Base CVSS score: HIGH (7.0)",
                                                impact = ImpactLevel.HIGH,
                                                multiplier = 1.0
                                            ),
                                            RiskFactorExplanation(
                                                name = "kev",
                                                contribution = 140.0,
                                                explanation = "Listed in CISA KEV catalog",
                                                impact = ImpactLevel.CRITICAL,
                                                multiplier = 2.0
                                            )
                                        ),
                                        totalScore = 140.0
                                    ),
                                    dependencyScope = "RUNTIME",
                                    dependabotUpdatePullRequestUrl = "https://github.com/navikt/tpt-backend/pull/123",
                                    publishedAt = "2024-01-15T10:30:00Z",
                                    cvssScore = 7.0
                                ),
                                GitHubVulnVulnerabilityDto(
                                    identifier = "CVE-2024-87654",
                                    packageName = "axios",
                                    packageEcosystem = "NPM",
                                    description = "Cross-site scripting vulnerability in frontend dependencies",
                                    summary = "XSS vulnerability in axios",
                                    vulnerabilityDetailsLink = "https://nvd.nist.gov/vuln/detail/CVE-2024-87654",
                                    riskScore = 45.0,
                                    riskScoreBreakdown = RiskScoreBreakdown(
                                        baseScore = 45.0,
                                        factors = listOf(
                                            RiskFactorExplanation(
                                                name = "severity",
                                                contribution = 45.0,
                                                explanation = "Base CVSS score: MEDIUM (4.5)",
                                                impact = ImpactLevel.MEDIUM,
                                                multiplier = 1.0
                                            )
                                        ),
                                        totalScore = 45.0
                                    ),
                                    dependencyScope = "DEVELOPMENT",
                                    dependabotUpdatePullRequestUrl = null,
                                    publishedAt = "2024-02-10T14:00:00Z",
                                    cvssScore = 4.5
                                )
                            )
                        ),
                        GitHubVulnRepositoryDto(
                            nameWithOwner = "navikt/security-tools",
                            vulnerabilities = listOf(
                                GitHubVulnVulnerabilityDto(
                                    identifier = "CVE-2024-76543",
                                    packageName = "com.example:vulnerable-lib",
                                    packageEcosystem = "MAVEN",
                                    description = "Dependency confusion vulnerability allowing malicious package injection",
                                    summary = "Dependency confusion in Maven package",
                                    vulnerabilityDetailsLink = "https://nvd.nist.gov/vuln/detail/CVE-2024-76543",
                                    riskScore = 210.0,
                                    riskScoreBreakdown = RiskScoreBreakdown(
                                        baseScore = 84.0,
                                        factors = listOf(
                                            RiskFactorExplanation(
                                                name = "severity",
                                                contribution = 84.0,
                                                explanation = "Base CVSS score: CRITICAL (8.4)",
                                                impact = ImpactLevel.CRITICAL,
                                                multiplier = 1.0
                                            ),
                                            RiskFactorExplanation(
                                                name = "epss",
                                                contribution = 126.0,
                                                explanation = "High exploitation probability (75%)",
                                                impact = ImpactLevel.HIGH,
                                                multiplier = 1.5
                                            ),
                                            RiskFactorExplanation(
                                                name = "kev",
                                                contribution = 210.0,
                                                explanation = "Listed in CISA KEV catalog",
                                                impact = ImpactLevel.CRITICAL,
                                                multiplier = 1.67
                                            )
                                        ),
                                        totalScore = 210.0
                                    ),
                                    dependencyScope = "RUNTIME",
                                    dependabotUpdatePullRequestUrl = "https://github.com/navikt/security-tools/pull/456",
                                    publishedAt = "2024-03-01T08:00:00Z",
                                    cvssScore = 8.4
                                )
                            )
                        )
                    )
                ),
                GitHubVulnTeamDto(
                    team = "team-b",
                    repositories = listOf(
                        GitHubVulnRepositoryDto(
                            nameWithOwner = "navikt/security-tools",
                            vulnerabilities = listOf(
                                GitHubVulnVulnerabilityDto(
                                    identifier = "CVE-2024-76543",
                                    packageName = "com.example:vulnerable-lib",
                                    packageEcosystem = "MAVEN",
                                    description = "Dependency confusion vulnerability allowing malicious package injection",
                                    summary = "Dependency confusion in Maven package",
                                    vulnerabilityDetailsLink = "https://nvd.nist.gov/vuln/detail/CVE-2024-76543",
                                    riskScore = 210.0,
                                    riskScoreBreakdown = RiskScoreBreakdown(
                                        baseScore = 84.0,
                                        factors = listOf(
                                            RiskFactorExplanation(
                                                name = "severity",
                                                contribution = 84.0,
                                                explanation = "Base CVSS score: CRITICAL (8.4)",
                                                impact = ImpactLevel.CRITICAL,
                                                multiplier = 1.0
                                            ),
                                            RiskFactorExplanation(
                                                name = "epss",
                                                contribution = 126.0,
                                                explanation = "High exploitation probability (75%)",
                                                impact = ImpactLevel.HIGH,
                                                multiplier = 1.5
                                            ),
                                            RiskFactorExplanation(
                                                name = "kev",
                                                contribution = 210.0,
                                                explanation = "Listed in CISA KEV catalog",
                                                impact = ImpactLevel.CRITICAL,
                                                multiplier = 1.67
                                            )
                                        ),
                                        totalScore = 210.0
                                    ),
                                    dependencyScope = "RUNTIME",
                                    dependabotUpdatePullRequestUrl = "https://github.com/navikt/security-tools/pull/456",
                                    publishedAt = "2024-03-01T08:00:00Z",
                                    cvssScore = 8.4
                                )
                            )
                        )
                    )
                )
            )
        )
    }
}

