package no.nav.tpt.plugins

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import kotlinx.serialization.json.Json
import no.nav.tpt.infrastructure.auth.MockTokenIntrospectionService
import no.nav.tpt.infrastructure.auth.TokenIntrospectionService
import no.nav.tpt.infrastructure.cisa.KevService
import no.nav.tpt.infrastructure.cisa.MockKevService
import no.nav.tpt.infrastructure.config.AppConfig
import no.nav.tpt.infrastructure.epss.EpssService
import no.nav.tpt.infrastructure.epss.MockEpssService
import no.nav.tpt.infrastructure.nais.MockNaisApiService
import no.nav.tpt.infrastructure.nais.NaisApiService
import no.nav.tpt.infrastructure.nvd.MockNvdRepository
import no.nav.tpt.infrastructure.nvd.MockNvdSyncService
import no.nav.tpt.infrastructure.nvd.NvdRepository
import no.nav.tpt.infrastructure.nvd.NvdSyncService
import no.nav.tpt.infrastructure.vulns.VulnServiceImpl
import org.flywaydb.core.Flyway
import org.jetbrains.exposed.sql.Database
import org.testcontainers.containers.GenericContainer
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.utility.DockerImageName

private var postgresContainer: PostgreSQLContainer<*>? = null
private var valkeyContainer: GenericContainer<*>? = null

fun getOrCreatePostgresContainer(): PostgreSQLContainer<*> {
    if (postgresContainer == null) {
        postgresContainer = PostgreSQLContainer(DockerImageName.parse("postgres:17"))
            .withDatabaseName("tpt")
            .withUsername("tpt")
            .withPassword("tpt")
        postgresContainer!!.start()
    }
    return postgresContainer!!
}

fun getOrCreateValkeyContainer(): GenericContainer<*> {
    if (valkeyContainer == null) {
        valkeyContainer = GenericContainer(DockerImageName.parse("ghcr.io/valkey-io/valkey:7.2-alpine"))
            .withExposedPorts(6379)
        valkeyContainer!!.start()
    }
    return valkeyContainer!!
}

val LocalDevDependenciesPlugin = createApplicationPlugin(name = "LocalDevDependencies") {
    val postgres = getOrCreatePostgresContainer()
    val valkey = getOrCreateValkeyContainer()

    val httpClient = HttpClient(CIO) {
        install(ContentNegotiation) {
            json(Json {
                prettyPrint = true
                isLenient = true
                ignoreUnknownKeys = true
                explicitNulls = false
                coerceInputValues = true
            })
        }
    }

    val tokenIntrospectionService: TokenIntrospectionService = MockTokenIntrospectionService()
    val naisApiService: NaisApiService = MockNaisApiService()
    val kevService: KevService = MockKevService()
    val epssService: EpssService = MockEpssService()

    val hikariConfig = HikariConfig().apply {
        jdbcUrl = postgres.jdbcUrl
        username = postgres.username
        password = postgres.password
        driverClassName = "org.postgresql.Driver"
        maximumPoolSize = 10
        minimumIdle = 2
        connectionTimeout = 30000
        isAutoCommit = false
        transactionIsolation = "TRANSACTION_REPEATABLE_READ"
    }
    val dataSource = HikariDataSource(hikariConfig)

    val flyway = Flyway.configure()
        .dataSource(dataSource)
        .locations("classpath:db/migration")
        .load()
    flyway.migrate()

    val database = Database.connect(dataSource)
    val nvdRepository: NvdRepository = MockNvdRepository()
    val nvdSyncService: NvdSyncService = MockNvdSyncService()

    val leaderElection = LeaderElection(httpClient)

    val riskScorer = no.nav.tpt.domain.risk.DefaultRiskScorer()
    val vulnService = VulnServiceImpl(naisApiService, kevService, epssService, nvdRepository, riskScorer)

    val config = AppConfig(
        naisTokenIntrospectionEndpoint = "http://localhost:8080/mock-introspection",
        naisApiUrl = "http://localhost:8080/mock-nais-api",
        naisApiToken = "mock-token",
        dbJdbcUrl = postgres.jdbcUrl,
        nvdApiUrl = "http://localhost:8080/mock-nvd-api",
        nvdApiKey = null,
        valkeyHost = valkey.host,
        valkeyPort = valkey.getMappedPort(6379),
        valkeyUsername = "default",
        valkeyPassword = "default",
        cacheTtlMinutes = 1L
    )

    val dependencies = Dependencies(
        appConfig = config,
        tokenIntrospectionService = tokenIntrospectionService,
        naisApiService = naisApiService,
        kevService = kevService,
        epssService = epssService,
        database = database,
        nvdRepository = nvdRepository,
        nvdSyncService = nvdSyncService,
        leaderElection = leaderElection,
        httpClient = httpClient,
        vulnService = vulnService
    )

    application.attributes.put(DependenciesKey, dependencies)
}

