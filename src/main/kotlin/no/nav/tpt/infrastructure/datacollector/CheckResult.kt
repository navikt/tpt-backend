package no.nav.tpt.infrastructure.datacollector

import kotlin.time.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CheckResultsForRepo(val repoName: String, val repoOwners: List<String>, val results : List<CheckResult>)

@Serializable
sealed class CheckResult {
    abstract val name: String
    abstract val whenChecked: Instant

    @Serializable
    data class AllGood(override val name: String,
                       override val whenChecked: Instant) :
        CheckResult()
    @Serializable
    data class NeedsWork(
        override val name: String,
        override val whenChecked: Instant,
        val reasons: List<String>
    ) : CheckResult()
}
