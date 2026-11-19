package no.nav.tpt.infrastructure.database

import java.sql.Connection
import java.sql.DriverManager
import java.sql.ResultSet
import kotlin.test.Test
import kotlin.test.assertEquals
import org.flywaydb.core.Flyway
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers

@Testcontainers
class RepositoryNamesMigrationTest {
    companion object {
        @Container
        private val postgres = PostgreSQLContainer<Nothing>("postgres:17-alpine")
    }

    @Test
    fun `should qualify legacy names and preserve the newest checks and GitHub snapshots`() {
        Flyway.configure()
            .dataSource(postgres.jdbcUrl, postgres.username, postgres.password)
            .target("32")
            .load()
            .migrate()

        DriverManager.getConnection(postgres.jdbcUrl, postgres.username, postgres.password).use { connection ->
            connection.createStatement().use { statement ->
                statement.executeUpdate(
                    """
                    INSERT INTO datacollector_checks (id, repo, check_name, result, updated_at) VALUES
                        ('bare-only', 'bare-only', 'check', 'NeedsWork', '2026-01-01 10:00:00'),
                        ('old-bare', 'newer-qualified', 'check', 'NeedsWork', '2026-01-01 10:00:00'),
                        ('new-qualified', 'navikt/newer-qualified', 'check', 'AllGood', '2026-01-02 10:00:00'),
                        ('new-bare', 'newer-bare', 'check', 'AllGood', '2026-01-02 10:00:00'),
                        ('old-qualified', 'navikt/newer-bare', 'check', 'NeedsWork', '2026-01-01 10:00:00'),
                        ('tied-bare', 'tied', 'check', 'NeedsWork', '2026-01-01 10:00:00'),
                        ('tied-qualified', 'navikt/tied', 'check', 'AllGood', '2026-01-01 10:00:00'),
                        ('extra-check', 'newer-qualified', 'extra', 'NeedsWork', '2026-01-01 10:00:00'),
                        ('other-owner', 'other/bare-only', 'check', 'NeedsWork', '2026-01-01 10:00:00');

                    INSERT INTO datacollector_check_failure_reasons (check_id, reason)
                    SELECT id, 'reason-' || id FROM datacollector_checks WHERE result = 'NeedsWork';

                    INSERT INTO datacollector_repo_owners (check_id, owner)
                    SELECT id, 'team-' || id FROM datacollector_checks;

                    INSERT INTO github_repositories (name_with_owner, nais_teams, created_at, updated_at) VALUES
                        ('bare-only', ARRAY['bare-only'], '2026-01-01', '2026-01-01'),
                        ('newer-qualified', ARRAY['old-bare'], '2026-01-01', '2026-01-01'),
                        ('navikt/newer-qualified', ARRAY['new-qualified'], '2026-01-01', '2026-01-02'),
                        ('newer-bare', ARRAY['new-bare'], '2026-01-01', '2026-01-02'),
                        ('navikt/newer-bare', ARRAY['old-qualified'], '2026-01-01', '2026-01-01'),
                        ('tied', ARRAY['tied-bare'], '2026-01-01', '2026-01-01'),
                        ('navikt/tied', ARRAY['tied-qualified'], '2026-01-01', '2026-01-01'),
                        ('other/bare-only', ARRAY['other-owner'], '2026-01-01', '2026-01-01'),
                        ('empty-newer', ARRAY['old-vulnerabilities'], '2026-01-01', '2026-01-01'),
                        ('navikt/empty-newer', ARRAY['no-vulnerabilities'], '2026-01-01', '2026-01-02');

                    INSERT INTO github_vulnerabilities (name_with_owner, severity, summary)
                    SELECT name_with_owner, 'HIGH', nais_teams[1]
                    FROM github_repositories WHERE name_with_owner <> 'navikt/empty-newer';

                    INSERT INTO github_vulnerability_identifiers (vulnerability_id, identifier_value, identifier_type)
                    SELECT id, summary, 'GHSA' FROM github_vulnerabilities;
                    """.trimIndent()
                )
            }

            Flyway.configure()
                .dataSource(postgres.jdbcUrl, postgres.username, postgres.password)
                .load()
                .migrate()

            val expectedCheckIds = setOf(
                "bare-only", "new-qualified", "new-bare", "tied-qualified", "extra-check", "other-owner"
            )
            assertEquals(
                mapOf(
                    ("navikt/bare-only" to "check") to "bare-only",
                    ("navikt/newer-qualified" to "check") to "new-qualified",
                    ("navikt/newer-bare" to "check") to "new-bare",
                    ("navikt/tied" to "check") to "tied-qualified",
                    ("navikt/newer-qualified" to "extra") to "extra-check",
                    ("other/bare-only" to "check") to "other-owner"
                ),
                connection.query("SELECT repo, check_name, id FROM datacollector_checks") {
                    (it.getString("repo") to it.getString("check_name")) to it.getString("id")
                }.toMap()
            )
            assertEquals(
                expectedCheckIds.associateWith { "team-$it" },
                connection.query("SELECT check_id, owner FROM datacollector_repo_owners") {
                    it.getString("check_id") to it.getString("owner")
                }.toMap()
            )
            assertEquals(
                setOf("bare-only", "extra-check", "other-owner").associateWith { "reason-$it" },
                connection.query("SELECT check_id, reason FROM datacollector_check_failure_reasons") {
                    it.getString("check_id") to it.getString("reason")
                }.toMap()
            )

            val expectedRepositories = mapOf(
                "navikt/bare-only" to "bare-only",
                "navikt/newer-qualified" to "new-qualified",
                "navikt/newer-bare" to "new-bare",
                "navikt/tied" to "tied-qualified",
                "other/bare-only" to "other-owner",
                "navikt/empty-newer" to "no-vulnerabilities"
            )
            assertEquals(
                expectedRepositories,
                connection.query("SELECT name_with_owner, nais_teams[1] AS team FROM github_repositories") {
                    it.getString("name_with_owner") to it.getString("team")
                }.toMap()
            )
            assertEquals(
                expectedRepositories - "navikt/empty-newer",
                connection.query(
                    """
                    SELECT v.name_with_owner, v.summary, i.identifier_value
                    FROM github_vulnerabilities v
                    JOIN github_vulnerability_identifiers i ON i.vulnerability_id = v.id
                    """.trimIndent()
                ) {
                    assertEquals(it.getString("summary"), it.getString("identifier_value"))
                    it.getString("name_with_owner") to it.getString("summary")
                }.toMap()
            )
            assertEquals(
                5,
                connection.query("SELECT COUNT(*) FROM github_vulnerabilities") { it.getInt(1) }.single()
            )
            assertEquals(
                5,
                connection.query("SELECT COUNT(*) FROM github_vulnerability_identifiers") { it.getInt(1) }.single()
            )
        }
    }

    private fun <T> Connection.query(sql: String, map: (ResultSet) -> T): List<T> =
        createStatement().use { statement ->
            statement.executeQuery(sql).use { rows ->
                buildList {
                    while (rows.next()) add(map(rows))
                }
            }
        }
}
