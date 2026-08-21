package no.nav.tpt.infrastructure.github


import org.jetbrains.exposed.v1.core.*
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.jdbc.*
import org.jetbrains.exposed.v1.jdbc.transactions.suspendTransaction
import org.slf4j.LoggerFactory
import java.time.Instant

class GitHubRepositoryImpl(private val database: Database) : GitHubRepository {
    private val logger = LoggerFactory.getLogger(GitHubRepositoryImpl::class.java)

    private suspend fun <T> dbQuery(block: suspend () -> T): T =
        suspendTransaction(database) { block() }

    override suspend fun upsertRepositoryData(message: GitHubRepositoryMessage): Unit = dbQuery {
        val repoIdentifier = message.nameWithOwner

        val existingRow = GitHubRepositories.selectAll()
            .where { GitHubRepositories.nameWithOwner eq repoIdentifier }
            .singleOrNull()

        if (existingRow != null) {
            GitHubRepositories.update({ GitHubRepositories.nameWithOwner eq repoIdentifier }) {
                message.naisTeams?.let { teams ->
                    it[naisTeams] = teams
                }
                it[updatedAt] = Instant.now()
            }

            message.vulnerabilities?.let {
                GitHubVulnerabilities.deleteWhere { nameWithOwner eq repoIdentifier }
            }
        } else {
            GitHubRepositories.insert {
                it[nameWithOwner] = repoIdentifier
                it[naisTeams] = message.naisTeams ?: emptyList()
                it[createdAt] = Instant.now()
                it[updatedAt] = Instant.now()
            }
        }

        message.vulnerabilities?.forEach { vuln ->
            val vulnId = GitHubVulnerabilities.insert {
                it[nameWithOwner] = repoIdentifier
                it[severity] = vuln.severity
                it[dependencyScope] = vuln.dependencyScope
                it[dependabotUpdatePullRequestUrl] = vuln.dependabotUpdatePullRequestUrl
                it[publishedAt] = vuln.publishedAt?.let { dateStr -> Instant.parse(dateStr) }
                it[cvssScore] = vuln.cvssScore?.toBigDecimal()
                it[summary] = vuln.summary
                it[packageEcosystem] = vuln.packageEcosystem
                it[packageName] = vuln.packageName
                it[createdAt] = Instant.now()
                it[updatedAt] = Instant.now()
            } get GitHubVulnerabilities.id

            vuln.identifiers.forEach { identifier ->
                GitHubVulnerabilityIdentifiers.insert {
                    it[vulnerabilityId] = vulnId
                    it[identifierValue] = identifier.value
                    it[identifierType] = identifier.type
                    it[createdAt] = Instant.now()
                }
            }
        }
    }

    override suspend fun updateCodeScanningStatus(repoName: String, status: String): Unit = dbQuery {
        GitHubRepositories.update({ GitHubRepositories.nameWithOwner eq repoName }) {
            it[GitHubRepositories.codeScanningStatus] = status
            it[updatedAt] = Instant.now()
        }
    }

    override suspend fun getRepository(nameWithOwner: String): GitHubRepositoryData? = dbQuery {
        GitHubRepositories.selectAll()
            .where { GitHubRepositories.nameWithOwner eq nameWithOwner }
            .mapNotNull { toGitHubRepositoryData(it) }
            .singleOrNull()
    }

    override suspend fun getVulnerabilities(nameWithOwner: String): List<GitHubVulnerabilityData> = dbQuery {
        val vulnerabilities = GitHubVulnerabilities.selectAll()
            .where { GitHubVulnerabilities.nameWithOwner eq nameWithOwner }
            .toList()

        vulnerabilities.map { vulnRow ->
            val vulnId = vulnRow[GitHubVulnerabilities.id]
            val identifiers = GitHubVulnerabilityIdentifiers.selectAll()
                .where { GitHubVulnerabilityIdentifiers.vulnerabilityId eq vulnId }
                .map { identRow ->
                    GitHubIdentifierData(
                        value = identRow[GitHubVulnerabilityIdentifiers.identifierValue],
                        type = identRow[GitHubVulnerabilityIdentifiers.identifierType]
                    )
                }

            GitHubVulnerabilityData(
                id = vulnId,
                nameWithOwner = vulnRow[GitHubVulnerabilities.nameWithOwner],
                severity = vulnRow[GitHubVulnerabilities.severity],
                identifiers = identifiers,
                dependencyScope = vulnRow[GitHubVulnerabilities.dependencyScope],
                dependabotUpdatePullRequestUrl = vulnRow[GitHubVulnerabilities.dependabotUpdatePullRequestUrl],
                publishedAt = vulnRow[GitHubVulnerabilities.publishedAt],
                cvssScore = vulnRow[GitHubVulnerabilities.cvssScore]?.toDouble(),
                summary = vulnRow[GitHubVulnerabilities.summary],
                packageEcosystem = vulnRow[GitHubVulnerabilities.packageEcosystem],
                packageName = vulnRow[GitHubVulnerabilities.packageName],
                createdAt = vulnRow[GitHubVulnerabilities.createdAt],
                updatedAt = vulnRow[GitHubVulnerabilities.updatedAt]
            )
        }
    }

    override suspend fun getAllRepositories(): List<GitHubRepositoryData> = dbQuery {
        GitHubRepositories.selectAll()
            .map { toGitHubRepositoryData(it) }
    }

    override suspend fun getRepositoriesByTeams(teamSlugs: List<String>): List<GitHubRepositoryData> = dbQuery {
        if (teamSlugs.isEmpty()) {
            return@dbQuery emptyList()
        }

        GitHubRepositories.selectAll()
            .map { toGitHubRepositoryData(it) }
            .filter { repo -> repo.naisTeams.any { it in teamSlugs } }
    }

    override suspend fun deleteRepositoriesExclusivelyOwnedBy(teamSlugs: List<String>): Unit = dbQuery {
        if (teamSlugs.isEmpty()) return@dbQuery
        val teamSlugsSet = teamSlugs.toSet()
        val exclusiveRepos = GitHubRepositories.selectAll()
            .map { Pair(it[GitHubRepositories.nameWithOwner], it[GitHubRepositories.naisTeams].toSet()) }
            .filter { (_, teams) -> teams.isNotEmpty() && teamSlugsSet.containsAll(teams) }
            .map { (name, _) -> name }

        if (exclusiveRepos.isNotEmpty()) {
            GitHubRepositories.deleteWhere { nameWithOwner inList exclusiveRepos }
        }
    }

    override suspend fun removeTeamsFromSharedRepositories(teamSlugs: List<String>): Unit = dbQuery {
        if (teamSlugs.isEmpty()) return@dbQuery
        val teamSlugsSet = teamSlugs.toSet()
        val sharedRepos = GitHubRepositories.selectAll()
            .map { Pair(it[GitHubRepositories.nameWithOwner], it[GitHubRepositories.naisTeams].toList()) }
            .filter { (_, teams) ->
                teams.any { it in teamSlugsSet } && !teamSlugsSet.containsAll(teams)
            }

        for ((name, teams) in sharedRepos) {
            val updatedTeams = teams.filter { it !in teamSlugsSet }
            GitHubRepositories.update({ GitHubRepositories.nameWithOwner eq name }) {
                it[naisTeams] = updatedTeams
                it[updatedAt] = Instant.now()
            }
        }
    }

    override suspend fun tryAcquireRefreshLock(teamSlug: String): Boolean =
        dbQuery {
            val now = Instant.now()
            val staleThreshold = now.minusSeconds(30 * 60)
            val lockDeadline = now.plusSeconds(15 * 60)

            GitHubTeamSyncMetadata.upsert(
                GitHubTeamSyncMetadata.teamSlug,
                onUpdateExclude = listOf(GitHubTeamSyncMetadata.createdAt),
                where = {
                    (GitHubTeamSyncMetadata.lastRefreshTriggeredAt less staleThreshold) and
                        (GitHubTeamSyncMetadata.syncLockedUntil.isNull() or (GitHubTeamSyncMetadata.syncLockedUntil lessEq now))
                },
            ) {
                it[GitHubTeamSyncMetadata.teamSlug] = teamSlug
                it[lastRefreshTriggeredAt] = Instant.EPOCH
                it[syncLockedUntil] = lockDeadline
                it[createdAt] = now
                it[updatedAt] = now
            }

            GitHubTeamSyncMetadata
                .selectAll()
                .where {
                    (GitHubTeamSyncMetadata.teamSlug eq teamSlug) and
                        (GitHubTeamSyncMetadata.syncLockedUntil eq lockDeadline)
                }
                .count() > 0
        }

    override suspend fun releaseRefreshLock(teamSlug: String): Unit =
        dbQuery {
            GitHubTeamSyncMetadata.update({ GitHubTeamSyncMetadata.teamSlug eq teamSlug }) {
                it[syncLockedUntil] = null
                it[lastRefreshTriggeredAt] = Instant.now()
                it[updatedAt] = Instant.now()
            }
        }

    private fun toGitHubRepositoryData(row: ResultRow): GitHubRepositoryData {
        return GitHubRepositoryData(
            nameWithOwner = row[GitHubRepositories.nameWithOwner],
            naisTeams = row[GitHubRepositories.naisTeams].toList(),
            usesDistroless = row[GitHubRepositories.usesDistroless],
            codeScanningStatus = row[GitHubRepositories.codeScanningStatus],
            createdAt = row[GitHubRepositories.createdAt],
            updatedAt = row[GitHubRepositories.updatedAt]
        )
    }
}
