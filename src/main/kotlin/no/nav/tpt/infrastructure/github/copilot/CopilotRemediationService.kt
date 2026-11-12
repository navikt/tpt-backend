package no.nav.tpt.infrastructure.github.copilot

import no.nav.tpt.domain.remediation.CopilotRemediationCallbackRequest
import no.nav.tpt.domain.remediation.CopilotRemediationCallbackResponse
import no.nav.tpt.domain.remediation.CopilotRemediationDto
import no.nav.tpt.domain.remediation.CopilotRemediationStartRequest
import no.nav.tpt.domain.remediation.CopilotRemediationStartResponse
import no.nav.tpt.domain.remediation.CopilotRemediationStatus
import no.nav.tpt.domain.remediation.CopilotRemediationsResponse
import no.nav.tpt.domain.user.UserContextService
import no.nav.tpt.domain.vulnerability.VulnerabilityRepository
import no.nav.tpt.infrastructure.enrichment.VulnerabilityEnrichmentService
import no.nav.tpt.infrastructure.github.GitHubRepository
import no.nav.tpt.infrastructure.github.GitHubVulnerabilityService
import no.nav.tpt.plugins.BadRequestException
import no.nav.tpt.plugins.ConflictException
import no.nav.tpt.plugins.ForbiddenException
import no.nav.tpt.plugins.NotFoundException
import no.nav.tpt.plugins.ServiceUnavailableException
import org.slf4j.LoggerFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import java.util.Base64

class CopilotRemediationService(
    private val authClient: GitHubUserAuthClient?,
    private val tasksClient: CopilotAgentTasksClient,
    private val remediationRepository: CopilotRemediationRepository,
    private val userContextService: UserContextService,
    private val gitHubRepository: GitHubRepository,
    private val vulnerabilityRepository: VulnerabilityRepository,
    private val gitHubVulnerabilityService: GitHubVulnerabilityService,
    private val vulnerabilityEnrichmentService: VulnerabilityEnrichmentService,
    private val clock: () -> Instant = Instant::now,
) {
    private val logger = LoggerFactory.getLogger(CopilotRemediationService::class.java)
    private val secureRandom = SecureRandom()

    val enabled: Boolean get() = authClient != null

    suspend fun list(email: String, groups: List<String>, repository: String): CopilotRemediationsResponse {
        if (!enabled) return CopilotRemediationsResponse(enabled = false, remediations = emptyList())
        validateRepository(repository)

        val canonicalRepository = accessibleRepository(email, groups, repository)
            ?: throw ForbiddenException("You do not have access to repository $repository")

        val remediations = remediationRepository.findByRepository(canonicalRepository).map {
            CopilotRemediationDto(
                repository = it.key.repository,
                vulnerabilityIdentifier = it.key.vulnerabilityIdentifier,
                packageName = it.key.packageName.ifEmpty { null },
                status = it.status,
                taskUrl = it.taskUrl,
                requestedAt = it.createdAt.toString(),
            )
        }
        return CopilotRemediationsResponse(enabled = true, remediations = remediations)
    }

    suspend fun start(
        email: String,
        groups: List<String>,
        request: CopilotRemediationStartRequest,
    ): CopilotRemediationStartResponse {
        val client = requireAuthClient()
        validateRepository(request.repository)
        validateReturnPath(request.returnPath)

        val context = resolveContext(
            email, groups, request.repository, request.vulnerabilityIdentifier, request.packageName, request.workloadId,
        )
        val key = context.toKey()

        val existing = remediationRepository.find(key)
        if (existing?.status == CopilotRemediationStatus.STARTED && !request.force) {
            return CopilotRemediationStartResponse(authorizeUrl = null, existingTaskUrl = existing.taskUrl)
        }

        val state = randomToken()
        val codeVerifier = randomToken()
        remediationRepository.saveAuthorizationRequest(
            CopilotAuthorizationRequest(
                state = state,
                codeVerifier = codeVerifier,
                requestedBy = email,
                key = key,
                workloadId = request.workloadId,
                returnPath = request.returnPath,
                expiresAt = clock().plus(AUTHORIZATION_REQUEST_TTL),
            ),
        )
        return CopilotRemediationStartResponse(
            authorizeUrl = client.authorizeUrl(state, codeChallenge(codeVerifier)),
            existingTaskUrl = null,
        )
    }

    suspend fun complete(
        email: String,
        groups: List<String>,
        request: CopilotRemediationCallbackRequest,
    ): CopilotRemediationCallbackResponse {
        val client = requireAuthClient()
        if (request.code.isBlank() || request.state.isBlank()) {
            throw BadRequestException("code and state are required")
        }

        val authorization = remediationRepository.consumeAuthorizationRequest(request.state)
            ?.takeIf { it.expiresAt.isAfter(clock()) }
            ?: throw BadRequestException("The authorization request is invalid or has expired. Please try again.")
        if (authorization.requestedBy != email) {
            throw ForbiddenException("The authorization request belongs to another user")
        }

        val context = resolveContext(
            email,
            groups,
            authorization.key.repository,
            authorization.key.vulnerabilityIdentifier,
            authorization.key.packageName.ifEmpty { null },
            authorization.workloadId,
        )

        val accessToken = try {
            client.exchangeCode(request.code, authorization.codeVerifier)
        } catch (e: GitHubApiException) {
            logger.warn("GitHub token exchange failed with status ${e.statusCode}")
            throw BadRequestException("GitHub authorization failed. Please try again.")
        }

        try {
            return startTask(accessToken, email, context, authorization.returnPath)
        } catch (e: GitHubApiException) {
            throw mapGitHubError(e)
        } finally {
            client.revokeToken(accessToken)
        }
    }

    private suspend fun startTask(
        accessToken: String,
        email: String,
        context: RemediationVulnerabilityContext,
        returnPath: String,
    ): CopilotRemediationCallbackResponse {
        val key = context.toKey()
        val now = clock()
        val existing = remediationRepository.find(key)

        var replaceableTaskId: String? = null
        if (existing?.status == CopilotRemediationStatus.STARTED && existing.taskId != null) {
            val task = tasksClient.getTask(accessToken, key.repository, existing.taskId)
            val restartable = if (task == null) {
                existing.updatedAt.isBefore(now.minus(INVISIBLE_TASK_RESTART_AFTER))
            } else {
                task.state in RESTARTABLE_STATES
            }
            if (!restartable) {
                return CopilotRemediationCallbackResponse(
                    taskUrl = existing.taskUrl ?: task?.htmlUrl,
                    returnPath = returnPath,
                    alreadyStarted = true,
                )
            }
            replaceableTaskId = existing.taskId
        }

        val claimed = remediationRepository.tryClaim(key, email, replaceableTaskId, now.minus(PENDING_CLAIM_TTL))
        if (!claimed) {
            return CopilotRemediationCallbackResponse(
                taskUrl = remediationRepository.find(key)?.taskUrl,
                returnPath = returnPath,
                alreadyStarted = true,
            )
        }

        val task = try {
            tasksClient.createTask(accessToken, key.repository, CopilotPromptBuilder.build(context))
        } catch (e: Exception) {
            remediationRepository.releaseClaim(key)
            throw e
        }
        remediationRepository.markStarted(key, task.id, task.htmlUrl)
        logger.info("Started Copilot task ${task.id} for ${key.vulnerabilityIdentifier} in ${key.repository}")

        return CopilotRemediationCallbackResponse(taskUrl = task.htmlUrl, returnPath = returnPath, alreadyStarted = false)
    }

    private suspend fun accessibleRepository(email: String, groups: List<String>, repository: String): String? {
        val teams = userContextService.getUserContext(email, groups).teams
        if (teams.isEmpty()) return null
        return gitHubRepository.getRepositoriesByTeams(teams)
            .map { it.nameWithOwner }
            .firstOrNull { it.equals(repository, ignoreCase = true) }
            ?: vulnerabilityRepository.getActiveVulnerabilitiesForTeams(teams)
                .mapNotNull { it.repository }
                .firstOrNull { it.equals(repository, ignoreCase = true) }
    }

    private suspend fun resolveContext(
        email: String,
        groups: List<String>,
        repository: String,
        identifier: String,
        packageName: String?,
        workloadId: String?,
    ): RemediationVulnerabilityContext {
        val context = if (workloadId != null) {
            vulnerabilityEnrichmentService.enrichVulnerabilitiesForUser(email, groups).teams
                .flatMap { it.workloads }
                .filter { it.id == workloadId && it.repository.equals(repository, ignoreCase = true) }
                .firstNotNullOfOrNull { workload ->
                    workload.vulnerabilities
                        .firstOrNull { it.identifier == identifier && it.packageName == packageName }
                        ?.let { vuln ->
                            RemediationVulnerabilityContext(
                                repository = workload.repository!!,
                                identifier = vuln.identifier,
                                packageName = vuln.packageName,
                                packageEcosystem = vuln.packageEcosystem,
                                dependencyScope = vuln.dependencyScope,
                                dependencyCategory = vuln.dependencyCategory,
                                summary = vuln.summary,
                                description = vuln.description,
                                detailsLink = vuln.vulnerabilityDetailsLink,
                                dependabotUpdatePullRequestUrl = vuln.dependabotUpdatePullRequestUrl,
                                workloadName = workload.name,
                                environment = workload.environment,
                            )
                        }
                }
        } else {
            gitHubVulnerabilityService.enrichVulnerabilitiesForUser(email, groups).teams
                .flatMap { it.repositories }
                .filter { it.nameWithOwner.equals(repository, ignoreCase = true) }
                .firstNotNullOfOrNull { repo ->
                    repo.vulnerabilities
                        .firstOrNull { it.identifier == identifier && it.packageName == packageName }
                        ?.let { vuln ->
                            RemediationVulnerabilityContext(
                                repository = repo.nameWithOwner,
                                identifier = vuln.identifier,
                                packageName = vuln.packageName,
                                packageEcosystem = vuln.packageEcosystem,
                                dependencyScope = vuln.dependencyScope,
                                dependencyCategory = null,
                                summary = vuln.summary,
                                description = vuln.description,
                                detailsLink = vuln.vulnerabilityDetailsLink,
                                dependabotUpdatePullRequestUrl = vuln.dependabotUpdatePullRequestUrl,
                                workloadName = null,
                                environment = null,
                            )
                        }
                }
        }
        context ?: throw NotFoundException("Vulnerability $identifier was not found in repository $repository")
        if (context.dependabotUpdatePullRequestUrl != null) {
            throw ConflictException("A Dependabot pull request already fixes this vulnerability")
        }
        return context
    }

    private fun mapGitHubError(e: GitHubApiException): Exception {
        logger.warn("GitHub API call failed with status ${e.statusCode}: ${e.message}")
        return when (e.statusCode) {
            401 -> BadRequestException("GitHub authorization failed. Please try again.")
            403 -> ForbiddenException(
                "GitHub denied the request. You need a Copilot Business or Enterprise seat, and Copilot cloud " +
                    "agent must be enabled for the repository.",
            )
            404 -> NotFoundException("Repository not found on GitHub, or the TPT GitHub App is not installed on it.")
            422 -> ConflictException("GitHub could not start the Copilot task for this repository.")
            else -> ServiceUnavailableException("GitHub is unavailable. Please try again later.")
        }
    }

    private fun requireAuthClient(): GitHubUserAuthClient =
        authClient ?: throw ServiceUnavailableException("Fix with Copilot is not configured")

    private fun validateRepository(repository: String) {
        if (!REPOSITORY_PATTERN.matches(repository)) {
            throw BadRequestException("repository must be in the format owner/name")
        }
    }

    private fun validateReturnPath(returnPath: String) {
        val valid = returnPath.length <= MAX_RETURN_PATH_LENGTH &&
            returnPath.startsWith("/") &&
            !returnPath.startsWith("//") &&
            !returnPath.contains('\\') &&
            returnPath.none { it.isISOControl() }
        if (!valid) throw BadRequestException("returnPath must be a relative path")
    }

    private fun randomToken(): String {
        val bytes = ByteArray(32).also { secureRandom.nextBytes(it) }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    private fun codeChallenge(codeVerifier: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(codeVerifier.toByteArray(Charsets.US_ASCII))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }

    private fun RemediationVulnerabilityContext.toKey() =
        RemediationKey(repository = repository, vulnerabilityIdentifier = identifier, packageName = packageName ?: "")

    companion object {
        private val REPOSITORY_PATTERN = Regex("^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
        private const val MAX_RETURN_PATH_LENGTH = 2048
        private val AUTHORIZATION_REQUEST_TTL: Duration = Duration.ofMinutes(10)
        private val PENDING_CLAIM_TTL: Duration = Duration.ofMinutes(5)
        private val INVISIBLE_TASK_RESTART_AFTER: Duration = Duration.ofDays(7)
        private val RESTARTABLE_STATES = setOf("failed", "cancelled", "timed_out")
    }
}
