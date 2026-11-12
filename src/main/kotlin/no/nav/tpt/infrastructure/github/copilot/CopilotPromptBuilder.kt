package no.nav.tpt.infrastructure.github.copilot

data class RemediationVulnerabilityContext(
    val repository: String,
    val identifier: String,
    val packageName: String?,
    val packageEcosystem: String?,
    val dependencyScope: String?,
    val dependencyCategory: String?,
    val summary: String?,
    val description: String?,
    val detailsLink: String?,
    val dependabotUpdatePullRequestUrl: String?,
    val workloadName: String?,
    val environment: String?,
)

object CopilotPromptBuilder {
    private const val MAX_DESCRIPTION_LENGTH = 2000
    private val CONTAINER_CATEGORIES = setOf("OS_PACKAGE", "CONTAINER")

    fun build(context: RemediationVulnerabilityContext): String = buildString {
        val packageText = context.packageName?.let { "package `$it`" } ?: "a dependency"
        val packageDetails = listOfNotNull(
            context.packageEcosystem?.let { "ecosystem: $it" },
            context.dependencyScope?.let { "scope: $it" },
        ).joinToString(", ")

        append("Fix security vulnerability ${context.identifier} in $packageText")
        if (packageDetails.isNotEmpty()) append(" ($packageDetails)")
        appendLine(" in repository ${context.repository}.")
        appendLine()

        context.summary?.takeIf { it.isNotBlank() }?.let { appendLine("Summary: ${it.trim()}") }
        context.description
            ?.takeIf { it.isNotBlank() && it != context.summary }
            ?.let { appendLine("Details: ${it.trim().take(MAX_DESCRIPTION_LENGTH)}") }
        context.detailsLink?.let { appendLine("Advisory: $it") }
        if (context.workloadName != null) {
            val environment = context.environment?.let { " in $it" } ?: ""
            appendLine("Detected in the deployed Nais workload `${context.workloadName}`$environment.")
        }
        appendLine()

        appendLine("Instructions:")
        if (context.dependencyCategory in CONTAINER_CATEGORIES) {
            appendLine(
                "- The vulnerable package comes from the container image. Update the base image in the " +
                    "Dockerfile (or the image reference used by the build) to a version where it is fixed.",
            )
        } else {
            appendLine(
                "- Find every manifest, lockfile or build file that pulls in the vulnerable version, " +
                    "including transitive dependencies, and upgrade to the first patched version or the newest " +
                    "compatible release.",
            )
        }
        appendLine("- Make any code changes the upgrade requires, and keep the change as small as possible.")
        appendLine("- Build the project and run the existing tests.")
        appendLine(
            "- Open a pull request that references ${context.identifier} and explains the change, including " +
                "any breaking changes or follow-up work.",
        )
    }
}
