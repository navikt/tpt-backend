package no.nav.tpt.infrastructure.datacollector

import kotlin.time.Clock
import no.nav.tpt.infrastructure.datacollector.CheckResult.AllGood

class FakeDataCollector : DataCollector {
    override suspend fun collectDataFor(teamSlugs: List<String>): List<CheckResult> = listOf(
        AllGood("TulleCheck", "tullerepo", Clock.System.now()),
        CheckResult.NeedsWork("YoloCheck", "yolorepo", Clock.System.now(), listOf("It has issues"))
    )
}