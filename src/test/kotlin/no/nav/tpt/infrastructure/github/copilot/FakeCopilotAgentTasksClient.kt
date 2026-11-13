package no.nav.tpt.infrastructure.github.copilot

import java.time.Instant

class FakeCopilotAgentTasksClient(
    var existingTaskState: String? = null,
    var createStatusCode: Int? = null,
    var createException: Exception? = null,
    var recoverableTask: AgentTask? = null,
) : CopilotAgentTasksClient {
    val createdTasks = mutableListOf<Pair<String, String>>()

    override suspend fun createTask(accessToken: String, repository: String, prompt: String): AgentTask {
        createStatusCode?.let { throw GitHubApiException(it, "Starting Copilot task failed") }
        createException?.let { throw it }
        createdTasks += repository to prompt
        val id = "task-${createdTasks.size}"
        return AgentTask(id = id, htmlUrl = "https://github.com/$repository/tasks/$id", state = "queued")
    }

    override suspend fun getTask(accessToken: String, repository: String, taskId: String): AgentTask? =
        existingTaskState?.let { AgentTask(id = taskId, htmlUrl = null, state = it) }

    override suspend fun findTaskCreatedBetween(
        accessToken: String,
        repository: String,
        from: Instant,
        to: Instant,
    ): AgentTask? = recoverableTask
}
