package no.nav.tpt.metrics

import io.micrometer.core.instrument.Clock
import io.micrometer.core.instrument.Counter
import io.micrometer.prometheusmetrics.PrometheusConfig
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry
import io.prometheus.metrics.model.registry.PrometheusRegistry

object BusinessMetrics {
    private val collectorRegistry = PrometheusRegistry.defaultRegistry

    private val registry =
        PrometheusMeterRegistry(
            PrometheusConfig.DEFAULT,
            collectorRegistry,
            Clock.SYSTEM,
        )

    private val checksPersistedCounter = Counter.builder("checks_persisted")
        .register(registry)

    private val checksPersistedFailCounter = Counter.builder("checks_persisted_failed")
        .register(registry)

    fun checksPersisted(n: Int = 1) = checksPersistedCounter.increment(n.toDouble())

    fun checksPersistingFailed(n: Int = 1) = checksPersistedFailCounter.increment(n.toDouble())
}