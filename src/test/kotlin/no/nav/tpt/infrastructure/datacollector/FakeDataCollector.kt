package no.nav.tpt.infrastructure.datacollector

class FakeDataCollector : DataCollector {
    val fakeRepo = FakeDatacollectorRepository()

    override suspend fun startCollectingDataFor(teamSlugs: List<String>) { }

    override suspend fun allChecksFor(teamSlugs: List<String>): List<CheckResultsForRepo> =
        fakeRepo.allForOwner(teamSlugs)

    override suspend fun suppress(repo: String, checkName: String) { }

    override suspend fun unsuppress(repo: String, checkName: String) { }
}

class FakeGitHubDataCollector : GitHubDataCollector {
    override suspend fun startCollectingDataFor(teamSlugs: List<String>) { }
}
