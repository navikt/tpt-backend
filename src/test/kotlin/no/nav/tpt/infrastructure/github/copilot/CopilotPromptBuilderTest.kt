package no.nav.tpt.infrastructure.github.copilot

import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertFalse

class CopilotPromptBuilderTest {
    private val context = RemediationVulnerabilityContext(
        repository = "navikt/app-a",
        identifier = "CVE-2026-0001",
        packageName = "com.example:lib",
        packageEcosystem = "MAVEN",
        dependencyScope = "RUNTIME",
        dependencyCategory = null,
        summary = "Remote code execution",
        description = "Remote code execution",
        detailsLink = "https://db.gcve.eu/vuln/CVE-2026-0001",
        dependabotUpdatePullRequestUrl = null,
        workloadName = null,
        environment = null,
    )

    @Test
    fun `should include vulnerability context and dependency upgrade instructions for application packages`() {
        val prompt = CopilotPromptBuilder.build(context)

        assertContains(prompt, "CVE-2026-0001 in package `com.example:lib` (ecosystem: MAVEN, scope: RUNTIME)")
        assertContains(prompt, "in repository navikt/app-a.")
        assertContains(prompt, "Advisory: https://db.gcve.eu/vuln/CVE-2026-0001")
        assertContains(prompt, "upgrade to the first patched version")
        assertFalse(prompt.contains("Details:"))
    }

    @Test
    fun `should ask for base image update for container packages in workloads`() {
        val prompt = CopilotPromptBuilder.build(
            context.copy(dependencyCategory = "OS_PACKAGE", workloadName = "app-a", environment = "prod-gcp"),
        )

        assertContains(prompt, "Detected in the deployed Nais workload `app-a` in prod-gcp.")
        assertContains(prompt, "Update the base image")
    }
}
