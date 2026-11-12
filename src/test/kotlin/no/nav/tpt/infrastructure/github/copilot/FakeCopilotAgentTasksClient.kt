package no.nav.tpt.infrastructure.github.copilot

class FakeCopilotAgentTasksClient(
    var existingTaskState: String? = null,
    var createStatusCode: Int? = null,
) : CopilotAgentTasksClient {
    val createdTasks = mutableListOf<Pair<String, String>>()

    override suspend fun createTask(accessToken: String, repository: String, prompt: String): AgentTask {
        createStatusCode?.let { throw GitHubApiException(it, "Starting Copilot task failed") }
        createdTasks += repository to prompt
        val id = "task-${createdTasks.size}"
        return AgentTask(id = id, htmlUrl = "https://github.com/$repository/tasks/$id", state = "queued")
    }

    override suspend fun getTask(accessToken: String, repository: String, taskId: String): AgentTask? =
        existingTaskState?.let { AgentTask(id = taskId, htmlUrl = null, state = it) }
}
