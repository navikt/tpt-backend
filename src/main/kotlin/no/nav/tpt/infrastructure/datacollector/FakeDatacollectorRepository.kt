package no.nav.tpt.infrastructure.datacollector

import kotlin.time.Clock

class FakeDatacollectorRepository: DatacollectorRepository {
    override suspend fun insert(checks: CheckResultsForRepo) {}

    override suspend fun allForOwner(teamSlugs: List<String>): Map<String, List<CheckResult>> {
        return mapOf(
            "someRepo" to listOf(
                CheckResult.AllGood("Tullesjekk", Clock.System.now()),
                CheckResult.NeedsWork("Dillesjekk", Clock.System.now(), listOf("Tingen er ikke gjort riktig"))
            ),
            "anotherRepo" to listOf(
                CheckResult.AllGood("BraSjekk", Clock.System.now()),
                CheckResult.NeedsWork("Dårligsjekk", Clock.System.now(), listOf("Her kan det forbedres"))
            )
        )
    }
}