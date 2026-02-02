package no.nav.tpt.infrastructure.github

import kotlinx.coroutines.Dispatchers
import no.nav.tpt.infrastructure.kafka.GitHubRepositoryMessage
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.transactions.experimental.newSuspendedTransaction
import org.slf4j.LoggerFactory
import java.time.Instant

class GitHubRepositoryImpl(private val database: Database) : GitHubRepository {
    private val logger = LoggerFactory.getLogger(GitHubRepositoryImpl::class.java)

    private suspend fun <T> dbQuery(block: suspend () -> T): T =
        newSuspendedTransaction(Dispatchers.IO, database) { block() }

    override suspend fun upsertRepositoryData(message: GitHubRepositoryMessage) = dbQuery {
        val repoIdentifier = message.getRepositoryIdentifier()

        val existingRow = GitHubRepositories.selectAll()
            .where { GitHubRepositories.nameWithOwner eq repoIdentifier }
            .singleOrNull()

        if (existingRow != null) {
            // Update existing repository - only update teams if present in message
            GitHubRepositories.update({ GitHubRepositories.nameWithOwner eq repoIdentifier }) {
                message.naisTeams?.let { teams ->
                    it[naisTeams] = teams
                }
                it[updatedAt] = Instant.now()
            }
            logger.info("Updated GitHub repository for: $repoIdentifier")

            // Only delete and update vulnerabilities if present in message
            message.vulnerabilities?.let {
                GitHubVulnerabilities.deleteWhere { nameWithOwner eq repoIdentifier }
                logger.info("Deleted existing vulnerabilities for: $repoIdentifier")
            }
        } else {
            // Insert new repository
            GitHubRepositories.insert {
                it[nameWithOwner] = repoIdentifier
                it[naisTeams] = message.naisTeams ?: emptyList()
                it[createdAt] = Instant.now()
                it[updatedAt] = Instant.now()
            }
            logger.info("Inserted new GitHub repository: $repoIdentifier")
        }

        // Insert vulnerabilities if present in message
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

        val vulnCount = message.vulnerabilities?.size ?: 0
        logger.info("Upserted $vulnCount vulnerabilities for: $repoIdentifier")
    }

    override suspend fun updateDockerfileFeatures(repoName: String, usesDistroless: Boolean) = dbQuery {
        val existingRow = GitHubRepositories.selectAll()
            .where { GitHubRepositories.nameWithOwner eq repoName }
            .singleOrNull()

        if (existingRow != null) {
            GitHubRepositories.update({ GitHubRepositories.nameWithOwner eq repoName }) {
                it[GitHubRepositories.usesDistroless] = usesDistroless
                it[updatedAt] = Instant.now()
            }
            logger.info("Updated dockerfile features for: $repoName (usesDistroless=$usesDistroless)")
        } else {
            GitHubRepositories.insert {
                it[nameWithOwner] = repoName
                it[naisTeams] = emptyList()
                it[GitHubRepositories.usesDistroless] = usesDistroless
                it[createdAt] = Instant.now()
                it[updatedAt] = Instant.now()
            }
            logger.info("Inserted new GitHub repository with dockerfile features: $repoName (usesDistroless=$usesDistroless)")
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

    private fun toGitHubRepositoryData(row: ResultRow): GitHubRepositoryData {
        return GitHubRepositoryData(
            nameWithOwner = row[GitHubRepositories.nameWithOwner],
            naisTeams = row[GitHubRepositories.naisTeams].toList(),
            usesDistroless = row[GitHubRepositories.usesDistroless],
            createdAt = row[GitHubRepositories.createdAt],
            updatedAt = row[GitHubRepositories.updatedAt]
        )
    }
}
