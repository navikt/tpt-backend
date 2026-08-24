package no.nav.tpt.infrastructure.datacollector

class FakeDatacollectorRepository: DatacollectorRepository {
    override suspend fun insert(checks: CheckResultsForRepo) {
        TODO("Not yet implemented")
    }

    override suspend fun allForRepo(name: String): List<CheckResult> {
        return emptyList()
    }

    override suspend fun allForOwner(teamSlugs: List<String>): List<CheckResult> {
        TODO("Not yet implemented")
    }
}