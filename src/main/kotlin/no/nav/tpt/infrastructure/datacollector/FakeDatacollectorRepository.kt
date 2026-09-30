package no.nav.tpt.infrastructure.datacollector

import kotlin.time.Clock
import no.nav.tpt.infrastructure.datacollector.Severity.HIGH
import no.nav.tpt.infrastructure.datacollector.Severity.LOW
import no.nav.tpt.infrastructure.datacollector.Severity.MEDIUM

class FakeDatacollectorRepository: DatacollectorRepository {
    override suspend fun insert(checks: CheckResultsForRepo) {}

    override suspend fun allForOwner(teamSlugs: List<String>): List<CheckResultsForRepo> = listOf(
        CheckResultsForRepo("someRepo", emptyList(), listOf(
            CheckResult.AllGood("Tullesjekk", "The description", LOW, Clock.System.now()),
            CheckResult.NeedsWork("Dillesjekk", "The description", MEDIUM,Clock.System.now(), listOf("Tingen er ikke gjort riktig"))
        )),
        CheckResultsForRepo("anotherRepo", emptyList(), listOf(
            CheckResult.AllGood("BraSjekk", "The description", MEDIUM,Clock.System.now()),
            CheckResult.NeedsWork("Dårligsjekk", "The description", HIGH,Clock.System.now(), listOf("Her kan det forbedres"))
        )),
    )
}
