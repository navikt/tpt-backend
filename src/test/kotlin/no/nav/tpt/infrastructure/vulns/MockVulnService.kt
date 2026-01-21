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
                    team = "appsec",
                    workloads = listOf(
                        VulnWorkloadDto(
                            id = "app-1",
                            name = "tpt-backend",
                            workloadType = "app",
                            environment = "prod-gcp",
                            repository = "navikt/tpt-backend",
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
                            vulnerabilities = listOf(
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
                        )
                    )
                ),
                VulnTeamDto(
                    team = "platform",
                    workloads = listOf(
                        VulnWorkloadDto(
                            id = "job-1",
                            name = "data-sync-job",
                            workloadType = "job",
                            environment = "prod-gcp",
                            repository = "navikt/data-sync",
                            vulnerabilities = listOf(
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

    override suspend fun fetchVulnerabilitiesForUser(email: String, bypassCache: Boolean): VulnResponse {
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

    override suspend fun fetchGitHubVulnerabilitiesForUser(email: String): GitHubVulnResponse {
        return GitHubVulnResponse(
            userRole = UserRole.DEVELOPER,
            teams = listOf(
                GitHubVulnTeamDto(
                    team = "appsec",
                    repositories = listOf(
                        GitHubVulnRepositoryDto(
                            name = "navikt/tpt-backend",
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
                            name = "navikt/security-tools",
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
                    team = "platform",
                    repositories = listOf(
                        GitHubVulnRepositoryDto(
                            name = "navikt/security-tools",
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

