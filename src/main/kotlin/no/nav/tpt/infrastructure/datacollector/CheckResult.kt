package no.nav.tpt.infrastructure.datacollector

import kotlin.time.Instant
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonNames
import no.nav.tpt.infrastructure.datacollector.Severity.UNKNOWN

enum class Severity {
    LOW, MEDIUM, HIGH, UNKNOWN
}

@Serializable
@OptIn(ExperimentalSerializationApi::class)
data class CheckResultsForRepo (
    @JsonNames("nameWithOwner") val repoName: String,
    val repoOwners: List<String>,
    val results: List<CheckResult>
)

@Serializable
sealed class CheckResult {
    abstract val name: String
    abstract val desc: String
    abstract val severity: Severity
    abstract val whenChecked: Instant

    @Serializable
    @SerialName("AllGood")
    data class AllGood(override val name: String,
                       override val desc: String = "missing desc",
                       override val severity: Severity = UNKNOWN,
                       override val whenChecked: Instant) :
        CheckResult()
    @Serializable
    @SerialName("NeedsWork")
    data class NeedsWork(
        override val name: String,
        override val desc: String = "missing desc",
        override val severity: Severity = UNKNOWN,
        override val whenChecked: Instant,
        val reasons: List<String>
    ) : CheckResult()
}
