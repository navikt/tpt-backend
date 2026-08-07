package no.nav.tpt.infrastructure.datacollector

import kotlin.time.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
sealed class CheckResult {
    abstract val name: String
    abstract val repo: String
    abstract val whenChecked: Instant

    @Serializable
    @SerialName("no.nav.checks.CheckResult.AllGood")
    data class AllGood(override val name: String, override val repo: String, override val whenChecked: Instant) :
        CheckResult()

    @Serializable
    @SerialName("no.nav.checks.CheckResult.NeedsWork")
    data class NeedsWork(
        override val name: String,
        override val repo: String,
        override val whenChecked: Instant,
        val reasons: List<String>
    ) : CheckResult()
}
