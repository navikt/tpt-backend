package no.nav.tpt.infrastructure.datacollector

class FakeDataCollector : DataCollector {
    override suspend fun startCollectingDataFor(teamSlugs: List<String>) { }

    override suspend fun allChecksFor(teamSlugs: List<String>): List<CheckResult> {
        TODO("Not yet implemented")
    }
}

class FakeGitHubDataCollector : GitHubDataCollector {
    override suspend fun startCollectingDataFor(teamSlugs: List<String>) { }
}
