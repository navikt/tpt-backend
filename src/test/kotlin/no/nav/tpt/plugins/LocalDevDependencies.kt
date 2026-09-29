package no.nav.tpt.plugins

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.UserAgent
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import kotlinx.serialization.json.Json
import no.nav.tpt.domain.user.UserContextService
import no.nav.tpt.infrastructure.auth.MockTokenIntrospectionService
import no.nav.tpt.infrastructure.auth.TokenIntrospectionService
import no.nav.tpt.infrastructure.config.AppConfig
import no.nav.tpt.infrastructure.datacollector.FakeDataCollector
import no.nav.tpt.infrastructure.datacollector.FakeDatacollectorRepository
import no.nav.tpt.infrastructure.datacollector.FakeGitHubDataCollector
import no.nav.tpt.infrastructure.github.GitHubRepository
import no.nav.tpt.infrastructure.github.MockGitHubRepositoryWithData
import no.nav.tpt.infrastructure.github.MockGitHubVulnerabilityService
import no.nav.tpt.infrastructure.nais.MockNaisApiService
import no.nav.tpt.infrastructure.nais.NaisApiService
import no.nav.tpt.infrastructure.sse.SseEventBus
import no.nav.tpt.infrastructure.teamkatalogen.MockTeamkatalogenService
import no.nav.tpt.infrastructure.teamkatalogen.TeamkatalogenService
import no.nav.tpt.infrastructure.user.UserContextServiceImpl
import no.nav.tpt.infrastructure.enrichment.MockVulnerabilityEnrichmentService
import no.nav.tpt.infrastructure.github.GitHubVulnerabilityServiceImpl
import org.flywaydb.core.Flyway
import org.jetbrains.exposed.v1.jdbc.Database
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.containers.wait.strategy.Wait
import org.testcontainers.containers.wait.strategy.WaitStrategy
import org.testcontainers.kafka.KafkaContainer
import org.testcontainers.utility.DockerImageName

private var postgresContainer: PostgreSQLContainer<*>? = null
private var kafkaContainer: KafkaContainer? = null
val KAFKA_WAIT_STRATEGY: WaitStrategy = Wait.forLogMessage(".*Transitioning from RECOVERY to RUNNING.*", 1)

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

fun getOrCreateKafkaContainer(): KafkaContainer {

    if (kafkaContainer == null) {
        kafkaContainer = KafkaContainer(DockerImageName.parse("apache/kafka:4.1.1"))
        kafkaContainer!!.start()
    }
    return kafkaContainer!!
}

val LocalDevDependenciesPlugin = createApplicationPlugin(name = "LocalDevDependencies") {
    val postgres = getOrCreatePostgresContainer()
    val kafka = getOrCreateKafkaContainer()

    val httpClient = HttpClient(CIO) {
        install(UserAgent) {
            agent = "tpt-backend (+https://github.com/navikt/tpt-backend)"
        }
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
    val naisApiService: NaisApiService = MockNaisApiService(
        mockTeamMemberships = listOf("team-lokal-utvikler", "team-b", "team-c")
    )
    val teamkatalogenService: TeamkatalogenService = MockTeamkatalogenService()
    val adminAuthorizationService = no.nav.tpt.infrastructure.user.AdminAuthorizationServiceImpl()
    val userContextService: UserContextService = UserContextServiceImpl(naisApiService, teamkatalogenService, adminAuthorizationService)

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

    val leaderElection = LeaderElection(httpClient)

    val gitHubRepository: GitHubRepository = MockGitHubRepositoryWithData()

    val localGcveRepository = no.nav.tpt.infrastructure.gcve.InMemoryGcveRepository()
    val localGcveSightingsRepository = no.nav.tpt.infrastructure.gcve.InMemoryGcveSightingsRepository()

    val vulnService = MockVulnerabilityEnrichmentService()

    val fallbackGitHubVulnerabilityService = GitHubVulnerabilityServiceImpl(
        gitHubRepository = gitHubRepository,
        gcveRepository = localGcveRepository,
        userContextService = userContextService,
        riskScorer = no.nav.tpt.domain.risk.DefaultRiskScorer(),
    )
    val gitHubVulnerabilityService = MockGitHubVulnerabilityService(fallbackGitHubVulnerabilityService)

    val mockVulnerabilityRepository = no.nav.tpt.infrastructure.vulnerability.MockVulnerabilityRepository.withSampleData()
    
    val mockVulnerabilityTeamSyncService = no.nav.tpt.infrastructure.vulnerability.VulnerabilityTeamSyncService(
        naisApiService = naisApiService,
        vulnerabilityRepository = mockVulnerabilityRepository
    )
    
    val mockAdminReportRepository = no.nav.tpt.infrastructure.admin.InMemoryAdminReportRepository()

    val mockVulnerabilityDataSyncJob = no.nav.tpt.infrastructure.vulnerability.VulnerabilityDataSyncJob(
        naisApiService = naisApiService,
        vulnerabilityTeamSyncService = mockVulnerabilityTeamSyncService,
        vulnerabilityRepository = mockVulnerabilityRepository,
        adminReportRepository = mockAdminReportRepository,
        teamDelayMs = 1000
    )
    
    val mockVulnerabilitySearchService = no.nav.tpt.infrastructure.vulnerability.VulnerabilitySearchService(
        vulnerabilityRepository = mockVulnerabilityRepository,
        slaPolicy = no.nav.tpt.domain.vulnerability.SlaPolicy(),
    )
    
    val mockAdminService = no.nav.tpt.infrastructure.admin.AdminServiceImpl(
        adminReportRepository = mockAdminReportRepository,
    )

    val config = AppConfig(
        naisTokenIntrospectionEndpoint = "http://localhost:8080/mock-introspection",
        naisApiUrl = "http://localhost:8080/mock-nais-api",
        naisTokenFilePath = "mock-token",
        dbJdbcUrl = postgres.jdbcUrl,
        teamkatalogenUrl = "http://localhost:8080/mock-teamkatalogen",
        adminGroups = null,
        naisTokenRetrievalEndpoint = "http://localhost:8080/token",
    )

    val localGcveClient = no.nav.tpt.infrastructure.gcve.GcveClient(httpClient, "https://db.gcve.eu/api")
    val sseEventBus = SseEventBus()
    val dataCollector = FakeDataCollector()
    val datacollectorRepository = FakeDatacollectorRepository()

    val dependencies = Dependencies(
        appConfig = config,
        tokenIntrospectionService = tokenIntrospectionService,
        naisApiService = naisApiService,
        database = database,
        leaderElection = leaderElection,
        httpClient = httpClient,
        vulnerabilityEnrichmentService = vulnService,
        teamkatalogenService = teamkatalogenService,
        userContextService = userContextService,
        adminAuthorizationService = adminAuthorizationService,
        adminService = mockAdminService,
        gitHubRepository = gitHubRepository,
        dataCollectorRepository = datacollectorRepository,
        gitHubVulnerabilityService = gitHubVulnerabilityService,
        vulnerabilityDataSyncJob = mockVulnerabilityDataSyncJob,
        vulnerabilitySearchService = mockVulnerabilitySearchService,
        vulnerabilityTeamSyncService = mockVulnerabilityTeamSyncService,
        gcveRepository = localGcveRepository,
        gcveSyncService = no.nav.tpt.infrastructure.gcve.GcveSyncService(localGcveClient, localGcveRepository),
        gcveSightingsRepository = localGcveSightingsRepository,
        gcveSightingsSyncService = no.nav.tpt.infrastructure.gcve.GcveSightingsSyncService(localGcveClient, localGcveSightingsRepository),
        sseEventBus = sseEventBus,
        kafkaProducerService = null,
        dataCollector = dataCollector,
        gitHubDataCollector = FakeGitHubDataCollector(),
    )

    application.attributes.put(DependenciesKey, dependencies)

    // Set Kafka environment variables for local development
    System.setProperty("KAFKA_BROKERS", "localhost:${kafka.getMappedPort(9092)}")
}
