package no.nav.tpt.infrastructure.datacollector

class FakeDataCollector : DataCollector {
    override suspend fun startCollectingDataFor(teamSlugs: List<String>) { }
}

class FakeGitHubDataCollector : GitHubDataCollector {
    override suspend fun startCollectingDataFor(teamSlugs: List<String>) { }
}
