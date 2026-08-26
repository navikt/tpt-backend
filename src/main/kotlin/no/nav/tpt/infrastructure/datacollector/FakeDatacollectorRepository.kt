package no.nav.tpt.infrastructure.datacollector

import kotlin.time.Clock
import no.nav.tpt.infrastructure.datacollector.Severity.HIGH
import no.nav.tpt.infrastructure.datacollector.Severity.LOW
import no.nav.tpt.infrastructure.datacollector.Severity.MEDIUM

class FakeDatacollectorRepository: DatacollectorRepository {
    override suspend fun insert(checks: CheckResultsForRepo) {}

    override suspend fun allForOwner(teamSlugs: List<String>): Map<String, List<CheckResult>> {
        return mapOf(
            "someRepo" to listOf(
                CheckResult.AllGood("Tullesjekk", "The description", LOW, Clock.System.now()),
                CheckResult.NeedsWork("Dillesjekk", "The description", MEDIUM,Clock.System.now(), listOf("Tingen er ikke gjort riktig"))
            ),
            "anotherRepo" to listOf(
                CheckResult.AllGood("BraSjekk", "The description", MEDIUM,Clock.System.now()),
                CheckResult.NeedsWork("Dårligsjekk", "The description", HIGH,Clock.System.now(), listOf("Her kan det forbedres"))
            )
        )
    }
}