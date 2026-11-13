package no.nav.tpt.infrastructure.github.copilot

import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.bearerAuth
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.parameter
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.http.encodeURLPathPart
import io.ktor.http.isSuccess
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.time.Instant

class CopilotAgentTasksClientImpl(
    private val httpClient: HttpClient,
    private val gitHubApiUrl: String,
) : CopilotAgentTasksClient {

    override suspend fun createTask(accessToken: String, repository: String, prompt: String): AgentTask {
        val response = httpClient.post(tasksUrl(repository)) {
            githubHeaders(accessToken)
            contentType(ContentType.Application.Json)
            setBody(CreateTaskRequest(prompt = prompt, createPullRequest = true))
        }
        if (!response.status.isSuccess()) {
            throw GitHubApiException(response.status.value, "Starting Copilot task failed")
        }
        return response.body<TaskResponse>().toAgentTask()
    }

    override suspend fun getTask(accessToken: String, repository: String, taskId: String): AgentTask? {
        val response = httpClient.get("${tasksUrl(repository)}/${taskId.encodeURLPathPart()}") {
            githubHeaders(accessToken)
        }
        if (response.status == HttpStatusCode.NotFound) return null
        if (!response.status.isSuccess()) {
            throw GitHubApiException(response.status.value, "Fetching Copilot task failed")
        }
        return response.body<TaskResponse>().toAgentTask()
    }

    override suspend fun findTaskCreatedBetween(
        accessToken: String,
        repository: String,
        from: Instant,
        to: Instant,
    ): AgentTask? {
        val response = httpClient.get(tasksUrl(repository)) {
            githubHeaders(accessToken)
            parameter("since", from.toString())
            parameter("sort", "created_at")
            parameter("direction", "asc")
            parameter("per_page", 100)
        }
        if (response.status == HttpStatusCode.NotFound) return null
        if (!response.status.isSuccess()) {
            throw GitHubApiException(response.status.value, "Listing Copilot tasks failed")
        }
        return response.body<TaskListResponse>().tasks
            .mapNotNull { task ->
                task.createdAt?.let(Instant::parse)?.takeIf { it in from..to }?.let { it to task }
            }
            .minByOrNull { (createdAt, _) -> createdAt }
            ?.second
            ?.toAgentTask()
    }

    private fun tasksUrl(repository: String): String {
        val (owner, repo) = repository.split("/", limit = 2)
        return "$gitHubApiUrl/agents/repos/${owner.encodeURLPathPart()}/${repo.encodeURLPathPart()}/tasks"
    }

    private fun HttpRequestBuilder.githubHeaders(accessToken: String) {
        bearerAuth(accessToken)
        header(HttpHeaders.Accept, "application/vnd.github+json")
        header("X-GitHub-Api-Version", GITHUB_API_VERSION)
    }

    @Serializable
    private data class CreateTaskRequest(
        val prompt: String,
        @SerialName("create_pull_request") val createPullRequest: Boolean,
    )

    @Serializable
    private data class TaskResponse(
        val id: String,
        @SerialName("html_url") val htmlUrl: String? = null,
        val state: String,
        @SerialName("created_at") val createdAt: String? = null,
    ) {
        fun toAgentTask() = AgentTask(id = id, htmlUrl = htmlUrl, state = state)
    }

    @Serializable
    private data class TaskListResponse(val tasks: List<TaskResponse>)
}
