package no.nav.tpt.infrastructure.database

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import no.nav.tpt.infrastructure.config.AppConfig
import org.flywaydb.core.Flyway
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.transactions.TransactionManager
import org.slf4j.LoggerFactory
import java.sql.Connection

object DatabaseFactory {
    private val logger = LoggerFactory.getLogger(DatabaseFactory::class.java)

    fun init(config: AppConfig): Database {
        logger.info("Initializing database connection using JDBC URL")

        val hikariConfig = HikariConfig().apply {
            jdbcUrl = config.dbJdbcUrl
            driverClassName = "org.postgresql.Driver"

            // Connection pool settings
            maximumPoolSize = 10
            minimumIdle = 2
            connectionTimeout = 30000 // 30 seconds

            // Performance tuning
            isAutoCommit = false
            transactionIsolation = "TRANSACTION_READ_COMMITTED"

            // Rewrite batch inserts into multi-row INSERT statements
            dataSourceProperties["reWriteBatchedInserts"] = "true"
        }

        val dataSource = HikariDataSource(hikariConfig)

        // Run Flyway migrations
        logger.info("Running Flyway migrations")
        val flyway = Flyway.configure()
            .dataSource(dataSource)
            .locations("classpath:db/migration")
            .load()

        val migrationsApplied = flyway.migrate()
        logger.info("Flyway migrations completed: ${migrationsApplied.migrationsExecuted} migrations applied")

        val database = Database.connect(dataSource)

        // Set transaction isolation level
        TransactionManager.manager.defaultIsolationLevel = Connection.TRANSACTION_READ_COMMITTED

        logger.info("Database connection initialized successfully")

        return database
    }

    fun close(database: Database) {
        logger.info("Closing database connection")
        TransactionManager.closeAndUnregister(database)
    }
}

