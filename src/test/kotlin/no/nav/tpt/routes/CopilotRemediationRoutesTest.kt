package no.nav.tpt.routes

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.Json
import no.nav.tpt.domain.remediation.CopilotRemediationCallbackResponse
import no.nav.tpt.domain.remediation.CopilotRemediationStartResponse
import no.nav.tpt.domain.remediation.CopilotRemediationStatus
import no.nav.tpt.domain.remediation.CopilotRemediationsResponse
import no.nav.tpt.infrastructure.auth.MockTokenIntrospectionService
import no.nav.tpt.infrastructure.github.GitHubIdentifierData
import no.nav.tpt.infrastructure.github.GitHubRepositoryData
import no.nav.tpt.infrastructure.github.GitHubVulnerabilityData
import no.nav.tpt.infrastructure.github.MockGitHubRepository
import no.nav.tpt.domain.vulnerability.VulnerabilitySearchResult
import no.nav.tpt.infrastructure.github.copilot.AgentTask
import no.nav.tpt.infrastructure.github.copilot.CopilotAuthorizationRequest
import no.nav.tpt.infrastructure.github.copilot.CopilotRemediation
import no.nav.tpt.infrastructure.github.copilot.FakeCopilotAgentTasksClient
import no.nav.tpt.infrastructure.github.copilot.FakeGitHubUserAuthClient
import no.nav.tpt.infrastructure.github.copilot.InMemoryCopilotRemediationRepository
import no.nav.tpt.infrastructure.github.copilot.RemediationKey
import no.nav.tpt.infrastructure.github.copilot.VulnerabilityRef
import no.nav.tpt.infrastructure.vulnerability.MockVulnerabilityRepository
import no.nav.tpt.infrastructure.nais.MockNaisApiService
import no.nav.tpt.plugins.testModule
import java.io.IOException
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CopilotRemediationRoutesTest {
    private val json = Json { ignoreUnknownKeys = true }
    private val now = Instant.parse("2026-11-01T12:00:00Z")
    private val user = "test@example.com"
    private val repo = "navikt/app-a"
    private val key = RemediationKey(repo, "CVE-2026-0001", "lib-a")

    private val tokenService = MockTokenIntrospectionService(preferredUsername = user)
    private val naisApi = MockNaisApiService(mockTeamMemberships = listOf("team-a"))
    private val gitHubRepository = MockGitHubRepository(
        mockRepositories = listOf(GitHubRepositoryData(repo, listOf("team-a"), now, now)),
        mockVulnerabilities = mapOf(
            repo to listOf(
                vulnerability(1, "CVE-2026-0001", "lib-a"),
                vulnerability(2, "CVE-2026-0002", "lib-b", dependabotPr = "https://github.com/$repo/pull/1"),
                vulnerability(3, "CVE-2026-0003", "org.example:library", dependabotPr = "https://github.com/$repo/pull/2"),
            ),
        ),
    )

    private val workloadRepository = MockVulnerabilityRepository(
        vulnerabilities = listOf(
            workloadVulnerability("CVE-2026-0001", "pkg:maven/lib-a@1.0.0"),
            workloadVulnerability("CVE-2026-0003", "pkg:maven/org.example/library@1.2.3"),
        ),
    )

    private fun workloadVulnerability(cve: String, purl: String) = VulnerabilitySearchResult(
        cveId = cve,
        teamSlug = "team-a",
        applicationName = "app-a",
        applicationNaisId = "app-a-id",
        workloadType = "app",
        environment = "prod-gcp",
        repository = "https://github.com/$repo",
        imageTag = null,
        ingressTypes = emptyList(),
        packageName = purl,
        packageType = "maven",
        severity = "HIGH",
        description = null,
        vulnerabilityDetailsLink = null,
        hasExternalIngress = false,
        suppressed = false,
        discoveredAt = now,
        lastSeenAt = now,
    )

    private fun workloadStartBody(identifier: String, purl: String) =
        """{"repository":"https://github.com/$repo","vulnerabilityIdentifier":"$identifier",""" +
            """"packageName":"$purl","workloadId":"app-a-id","returnPath":"/nb"}"""

    private fun vulnerability(id: Int, cve: String, packageName: String, dependabotPr: String? = null) =
        GitHubVulnerabilityData(
            id = id,
            nameWithOwner = repo,
            severity = "HIGH",
            identifiers = listOf(GitHubIdentifierData(cve, "CVE")),
            dependabotUpdatePullRequestUrl = dependabotPr,
            summary = "Remote code execution in $packageName",
            packageEcosystem = "MAVEN",
            packageName = packageName,
            createdAt = now,
            updatedAt = now,
        )

    private fun startBody(identifier: String = "CVE-2026-0001", packageName: String = "lib-a", force: Boolean = false) =
        """{"repository":"$repo","vulnerabilityIdentifier":"$identifier","packageName":"$packageName",""" +
            """"returnPath":"/nb/github","force":$force}"""

    private fun ApplicationTestBuilder.setup(
        tasksClient: FakeCopilotAgentTasksClient = FakeCopilotAgentTasksClient(),
        repository: InMemoryCopilotRemediationRepository = InMemoryCopilotRemediationRepository(),
        authClient: FakeGitHubUserAuthClient? = FakeGitHubUserAuthClient(),
    ) {
        application {
            testModule(
                tokenIntrospectionService = tokenService,
                naisApiService = naisApi,
                gitHubRepository = gitHubRepository,
                vulnerabilityRepository = workloadRepository,
                copilotAuthClient = authClient,
                copilotTasksClient = tasksClient,
                copilotRemediationRepository = repository,
            )
        }
    }

    private suspend fun ApplicationTestBuilder.start(body: String): HttpResponse =
        client.post("/remediations/copilot") {
            header(HttpHeaders.Authorization, "Bearer token")
            contentType(ContentType.Application.Json)
            setBody(body)
        }

    private suspend fun ApplicationTestBuilder.callback(state: String, code: String = "good"): HttpResponse =
        client.post("/remediations/copilot/callback") {
            header(HttpHeaders.Authorization, "Bearer token")
            contentType(ContentType.Application.Json)
            setBody("""{"code":"$code","state":"$state"}""")
        }

    private fun stateFrom(response: CopilotRemediationStartResponse): String =
        Url(response.authorizeUrl!!).parameters["state"]!!

    private fun startedRemediation(taskId: String) = CopilotRemediation(
        key = key,
        status = CopilotRemediationStatus.STARTED,
        taskId = taskId,
        taskUrl = "https://github.com/$repo/tasks/$taskId",
        requestedBy = "colleague@example.com",
        createdAt = now,
        updatedAt = now,
    )

    @Test
    fun `should report feature disabled when GitHub App is not configured`() = testApplication {
        setup(authClient = null)

        val response = client.get("/remediations/copilot?repository=$repo") {
            header(HttpHeaders.Authorization, "Bearer token")
        }

        assertEquals(HttpStatusCode.OK, response.status)
        assertFalse(json.decodeFromString<CopilotRemediationsResponse>(response.bodyAsText()).enabled)
    }

    @Test
    fun `should start Copilot task and revoke token when callback completes`() = testApplication {
        val tasksClient = FakeCopilotAgentTasksClient()
        val authClient = FakeGitHubUserAuthClient()
        setup(tasksClient = tasksClient, authClient = authClient)

        val startResponse = start(startBody())
        assertEquals(HttpStatusCode.OK, startResponse.status)
        val state = stateFrom(json.decodeFromString(startResponse.bodyAsText()))

        val callbackResponse = callback(state)

        assertEquals(HttpStatusCode.Created, callbackResponse.status)
        val body = json.decodeFromString<CopilotRemediationCallbackResponse>(callbackResponse.bodyAsText())
        assertEquals("https://github.com/$repo/tasks/task-1", body.taskUrl)
        assertEquals("/nb/github", body.returnPath)
        assertEquals(1, tasksClient.createdTasks.size)
        assertTrue(tasksClient.createdTasks.single().second.contains("CVE-2026-0001"))
        assertEquals(listOf("ghu_test"), authClient.revokedTokens)

        val list = client.get("/remediations/copilot?repository=$repo") {
            header(HttpHeaders.Authorization, "Bearer token")
        }
        val remediation = json.decodeFromString<CopilotRemediationsResponse>(list.bodyAsText()).remediations.single()
        assertEquals(CopilotRemediationStatus.STARTED, remediation.status)
        assertEquals("CVE-2026-0001", remediation.vulnerabilityIdentifier)
    }

    @Test
    fun `should reject reused state when callback is replayed`() = testApplication {
        setup()
        val state = stateFrom(json.decodeFromString(start(startBody()).bodyAsText()))
        callback(state)

        val replay = callback(state)

        assertEquals(HttpStatusCode.BadRequest, replay.status)
    }

    @Test
    fun `should return existing task without authorizing when task already started`() = testApplication {
        val repository = InMemoryCopilotRemediationRepository().apply { remediations[key] = startedRemediation("old") }
        setup(repository = repository)

        val response = start(startBody())

        val body = json.decodeFromString<CopilotRemediationStartResponse>(response.bodyAsText())
        assertNull(body.authorizeUrl)
        assertEquals("https://github.com/$repo/tasks/old", body.existingTaskUrl)
    }

    @Test
    fun `should not start new task when forced restart finds active task`() = testApplication {
        val repository = InMemoryCopilotRemediationRepository().apply { remediations[key] = startedRemediation("old") }
        val tasksClient = FakeCopilotAgentTasksClient(existingTaskState = "in_progress")
        setup(tasksClient = tasksClient, repository = repository)

        val state = stateFrom(json.decodeFromString(start(startBody(force = true)).bodyAsText()))
        val response = callback(state)

        assertEquals(HttpStatusCode.OK, response.status)
        assertTrue(json.decodeFromString<CopilotRemediationCallbackResponse>(response.bodyAsText()).alreadyStarted)
        assertTrue(tasksClient.createdTasks.isEmpty())
    }

    @Test
    fun `should start new task when forced restart finds failed task`() = testApplication {
        val repository = InMemoryCopilotRemediationRepository().apply { remediations[key] = startedRemediation("old") }
        val tasksClient = FakeCopilotAgentTasksClient(existingTaskState = "failed")
        setup(tasksClient = tasksClient, repository = repository)

        val state = stateFrom(json.decodeFromString(start(startBody(force = true)).bodyAsText()))
        val response = callback(state)

        assertEquals(HttpStatusCode.Created, response.status)
        assertEquals("task-1", repository.remediations.getValue(key).taskId)
    }

    @Test
    fun `should release claim when GitHub rejects task creation`() = testApplication {
        val repository = InMemoryCopilotRemediationRepository()
        setup(tasksClient = FakeCopilotAgentTasksClient(createStatusCode = 403), repository = repository)

        val state = stateFrom(json.decodeFromString(start(startBody()).bodyAsText()))
        val response = callback(state)

        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertTrue(repository.remediations.isEmpty())
    }

    @Test
    fun `should not restart task when its state is not visible to the user`() = testApplication {
        val repository = InMemoryCopilotRemediationRepository().apply {
            remediations[key] = startedRemediation("old").copy(updatedAt = now.minusSeconds(30L * 24 * 3600))
        }
        val tasksClient = FakeCopilotAgentTasksClient(existingTaskState = null)
        setup(tasksClient = tasksClient, repository = repository)

        val state = stateFrom(json.decodeFromString(start(startBody(force = true)).bodyAsText()))
        val response = callback(state)

        assertTrue(json.decodeFromString<CopilotRemediationCallbackResponse>(response.bodyAsText()).alreadyStarted)
        assertTrue(tasksClient.createdTasks.isEmpty())
    }

    @Test
    fun `should keep claim and revoke token when task creation outcome is unknown`() = testApplication {
        val repository = InMemoryCopilotRemediationRepository()
        val authClient = FakeGitHubUserAuthClient()
        setup(
            tasksClient = FakeCopilotAgentTasksClient(createException = IOException("connection reset")),
            repository = repository,
            authClient = authClient,
        )

        val state = stateFrom(json.decodeFromString(start(startBody()).bodyAsText()))
        callback(state)

        assertEquals(CopilotRemediationStatus.PENDING, repository.remediations.getValue(key).status)
        assertEquals(listOf("ghu_test"), authClient.revokedTokens)
    }

    @Test
    fun `should adopt task created by a stale claim instead of starting another`() = testApplication {
        val repository = InMemoryCopilotRemediationRepository().apply {
            remediations[key] = startedRemediation("unused").copy(
                status = CopilotRemediationStatus.PENDING,
                taskId = null,
                taskUrl = null,
                updatedAt = Instant.now().minusSeconds(3600),
            )
        }
        val tasksClient = FakeCopilotAgentTasksClient(
            existingTaskState = "in_progress",
            recoverableTask = AgentTask("lost", "https://github.com/$repo/tasks/lost", "in_progress"),
        )
        setup(tasksClient = tasksClient, repository = repository)

        val state = stateFrom(json.decodeFromString(start(startBody()).bodyAsText()))
        val response = callback(state)

        val body = json.decodeFromString<CopilotRemediationCallbackResponse>(response.bodyAsText())
        assertTrue(body.alreadyStarted)
        assertEquals("https://github.com/$repo/tasks/lost", body.taskUrl)
        assertEquals("lost", repository.remediations.getValue(key).taskId)
        assertTrue(tasksClient.createdTasks.isEmpty())
    }

    @Test
    fun `should deduplicate workload and GitHub requests for the same package`() = testApplication {
        val repository = InMemoryCopilotRemediationRepository().apply { remediations[key] = startedRemediation("old") }
        setup(repository = repository)

        val response = start(workloadStartBody("CVE-2026-0001", "pkg:maven/lib-a@1.0.0"))

        assertEquals(HttpStatusCode.OK, response.status)
        val body = json.decodeFromString<CopilotRemediationStartResponse>(response.bodyAsText())
        assertEquals("https://github.com/$repo/tasks/old", body.existingTaskUrl)
    }

    @Test
    fun `should return 409 for workload vulnerability when GitHub has a Dependabot pull request`() = testApplication {
        setup()

        val response = start(workloadStartBody("CVE-2026-0003", "pkg:maven/org.example/library@1.2.3"))

        assertEquals(HttpStatusCode.Conflict, response.status)
    }

    @Test
    fun `should return 409 when Dependabot pull request exists`() = testApplication {
        setup()

        val response = start(startBody(identifier = "CVE-2026-0002", packageName = "lib-b"))

        assertEquals(HttpStatusCode.Conflict, response.status)
    }

    @Test
    fun `should return 404 when vulnerability is not in the user's repositories`() = testApplication {
        setup()

        val response = start(startBody(identifier = "CVE-2026-9999"))

        assertEquals(HttpStatusCode.NotFound, response.status)
    }

    @Test
    fun `should return 403 when listing remediations for another team's repository`() = testApplication {
        setup()

        val response = client.get("/remediations/copilot?repository=navikt/other") {
            header(HttpHeaders.Authorization, "Bearer token")
        }

        assertEquals(HttpStatusCode.Forbidden, response.status)
    }

    @Test
    fun `should reject absolute return path`() = testApplication {
        setup()

        val response = start(startBody().replace("/nb/github", "//evil.example.com"))

        assertEquals(HttpStatusCode.BadRequest, response.status)
    }

    @Test
    fun `should reject callback when state belongs to another user`() = testApplication {
        val repository = InMemoryCopilotRemediationRepository().apply {
            authorizationRequests["other-state"] = CopilotAuthorizationRequest(
                state = "other-state",
                codeVerifier = "verifier",
                requestedBy = "colleague@example.com",
                vulnerability = VulnerabilityRef(repo, "CVE-2026-0001", "lib-a"),
                workloadId = null,
                returnPath = "/",
                expiresAt = Instant.now().plusSeconds(600),
            )
        }
        val tasksClient = FakeCopilotAgentTasksClient()
        setup(tasksClient = tasksClient, repository = repository)

        val response = callback("other-state")

        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertTrue(tasksClient.createdTasks.isEmpty())
    }
}
