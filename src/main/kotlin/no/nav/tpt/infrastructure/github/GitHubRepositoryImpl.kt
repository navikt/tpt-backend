package no.nav.tpt.infrastructure.github

import no.nav.tpt.infrastructure.kafka.GitHubRepositoryMessage
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
        val repoIdentifier = message.getRepositoryIdentifier()

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

    override suspend fun updateDockerfileFeatures(repoName: String, usesDistroless: Boolean): Unit = dbQuery {
        GitHubRepositories.update({ GitHubRepositories.nameWithOwner eq repoName }) {
            it[GitHubRepositories.usesDistroless] = usesDistroless
            it[updatedAt] = Instant.now()
        }
        Unit
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

    override suspend fun getVulnerabilitiesByRepos(nameWithOwners: List<String>): Map<String, List<GitHubVulnerabilityData>> = dbQuery {
        if (nameWithOwners.isEmpty()) return@dbQuery emptyMap()

        val rows = (GitHubVulnerabilities leftJoin GitHubVulnerabilityIdentifiers)
            .selectAll()
            .where { GitHubVulnerabilities.nameWithOwner inList nameWithOwners }
            .toList()

        val vulnRowsById = LinkedHashMap<Int, Pair<ResultRow, MutableList<GitHubIdentifierData>>>()
        for (row in rows) {
            val vulnId = row[GitHubVulnerabilities.id]
            val entry = vulnRowsById.getOrPut(vulnId) { row to mutableListOf() }
            val identValue = row.getOrNull(GitHubVulnerabilityIdentifiers.identifierValue)
            if (identValue != null) {
                entry.second.add(
                    GitHubIdentifierData(
                        value = identValue,
                        type = row[GitHubVulnerabilityIdentifiers.identifierType]
                    )
                )
            }
        }

        vulnRowsById.values
            .map { (row, identifiers) ->
                GitHubVulnerabilityData(
                    id = row[GitHubVulnerabilities.id],
                    nameWithOwner = row[GitHubVulnerabilities.nameWithOwner],
                    severity = row[GitHubVulnerabilities.severity],
                    identifiers = identifiers,
                    dependencyScope = row[GitHubVulnerabilities.dependencyScope],
                    dependabotUpdatePullRequestUrl = row[GitHubVulnerabilities.dependabotUpdatePullRequestUrl],
                    publishedAt = row[GitHubVulnerabilities.publishedAt],
                    cvssScore = row[GitHubVulnerabilities.cvssScore]?.toDouble(),
                    summary = row[GitHubVulnerabilities.summary],
                    packageEcosystem = row[GitHubVulnerabilities.packageEcosystem],
                    packageName = row[GitHubVulnerabilities.packageName],
                    createdAt = row[GitHubVulnerabilities.createdAt],
                    updatedAt = row[GitHubVulnerabilities.updatedAt]
                )
            }
            .groupBy { it.nameWithOwner }
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
            .where {
                object : Op<Boolean>() {
                    override fun toQueryBuilder(queryBuilder: QueryBuilder): Unit = queryBuilder {
                        append(GitHubRepositories.naisTeams)
                        append(" && ARRAY[")
                        teamSlugs.forEachIndexed { i, team ->
                            if (i > 0) append(", ")
                            append(stringParam(team))
                        }
                        append("]::text[]")
                    }
                }
            }
            .map { toGitHubRepositoryData(it) }
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
