package no.nav.tpt.infrastructure.github

import org.jetbrains.exposed.sql.ReferenceOption
import org.jetbrains.exposed.sql.Table
import org.jetbrains.exposed.sql.javatime.timestamp
import java.time.Instant

object GitHubRepositories : Table("github_repositories") {
    val repositoryName = varchar("repository_name", 500)
    val naisTeams = array<String>("nais_teams")
    val createdAt = timestamp("created_at").default(Instant.now())
    val updatedAt = timestamp("updated_at").default(Instant.now())

    override val primaryKey = PrimaryKey(repositoryName)
}

object GitHubVulnerabilities : Table("github_vulnerabilities") {
    val id = integer("id").autoIncrement()
    val repositoryName = varchar("repository_name", 500).references(GitHubRepositories.repositoryName, onDelete = ReferenceOption.CASCADE)
    val severity = varchar("severity", 20)
    val createdAt = timestamp("created_at").default(Instant.now())
    val updatedAt = timestamp("updated_at").default(Instant.now())

    override val primaryKey = PrimaryKey(id)
}

object GitHubVulnerabilityIdentifiers : Table("github_vulnerability_identifiers") {
    val id = integer("id").autoIncrement()
    val vulnerabilityId = integer("vulnerability_id").references(GitHubVulnerabilities.id, onDelete = ReferenceOption.CASCADE)
    val identifierValue = varchar("identifier_value", 100)
    val identifierType = varchar("identifier_type", 20)
    val createdAt = timestamp("created_at").default(Instant.now())

    override val primaryKey = PrimaryKey(id)
}

data class GitHubRepositoryData(
    val repositoryName: String,
    val naisTeams: List<String>,
    val createdAt: Instant,
    val updatedAt: Instant
)

data class GitHubVulnerabilityData(
    val id: Int,
    val repositoryName: String,
    val severity: String,
    val identifiers: List<GitHubIdentifierData>,
    val createdAt: Instant,
    val updatedAt: Instant
)

data class GitHubIdentifierData(
    val value: String,
    val type: String
)
