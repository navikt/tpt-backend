package no.nav.tpt.metrics

import io.micrometer.core.instrument.Clock
import io.micrometer.core.instrument.Counter
import io.micrometer.core.instrument.Timer
import io.micrometer.prometheusmetrics.PrometheusConfig
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry
import io.prometheus.metrics.model.registry.PrometheusRegistry
import java.util.concurrent.TimeUnit

object TPTMetrics {
    private val collectorRegistry = PrometheusRegistry.defaultRegistry

    val registry =
        PrometheusMeterRegistry(
            PrometheusConfig.DEFAULT,
            collectorRegistry,
            Clock.SYSTEM,
        )

    private val checksPersistedCounter by lazy {
        Counter.builder("checks_persisted").register(registry)
    }

    private val checksPersistedFailCounter by lazy {
        Counter.builder("checks_persisted_failed").register(registry)
    }

    fun checksPersisted(n: Int = 1) = checksPersistedCounter.increment(n.toDouble())

    fun checksPersistingFailed(n: Int = 1) = checksPersistedFailCounter.increment(n.toDouble())

    fun recordTeamSyncDuration(teamSlug: String, result: String, durationMs: Long) {
        Timer.builder("team_sync_duration")
            .description("Time taken to sync vulnerabilities for a single team from Nais API")
            .tags("team", teamSlug, "result", result)
            .register(registry)
            .record(durationMs, TimeUnit.MILLISECONDS)
    }
}