package no.nav.tpt.infrastructure.github.copilot

import java.time.Instant

const val GITHUB_API_VERSION = "2026-03-10"

data class AgentTask(
    val id: String,
    val htmlUrl: String?,
    val state: String,
)

interface CopilotAgentTasksClient {
    suspend fun createTask(accessToken: String, repository: String, prompt: String): AgentTask

    /** Returns null when the task does not exist or is not visible to the user. */
    suspend fun getTask(accessToken: String, repository: String, taskId: String): AgentTask?

    /** Returns the earliest task visible to the user that was created within [from] and [to], if any. */
    suspend fun findTaskCreatedBetween(accessToken: String, repository: String, from: Instant, to: Instant): AgentTask?
}
