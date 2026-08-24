package no.nav.tpt.infrastructure.datacollector

class FakeDataCollector : DataCollector {
    val fakeRepo = FakeDatacollectorRepository()

    override suspend fun startCollectingDataFor(teamSlugs: List<String>) { }

    override suspend fun allChecksFor(teamSlugs: List<String>): List<CheckResult> =
        fakeRepo.allForOwner(teamSlugs)
}

class FakeGitHubDataCollector : GitHubDataCollector {
    override suspend fun startCollectingDataFor(teamSlugs: List<String>) { }
}
