package no.nav.tpt.infrastructure.datacollector

import kotlin.time.Clock

class FakeDatacollectorRepository: DatacollectorRepository {
    override suspend fun insert(checks: CheckResultsForRepo) {}

    override suspend fun allForOwner(teamSlugs: List<String>): List<CheckResult> {
        return listOf(
            CheckResult.AllGood("Tullesjekk", Clock.System.now()),
            CheckResult.NeedsWork("Dillesjekk", Clock.System.now(), listOf("Tingen er ikke gjort riktig"))
        )
    }
}