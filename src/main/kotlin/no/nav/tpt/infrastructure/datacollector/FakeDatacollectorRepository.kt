package no.nav.tpt.infrastructure.datacollector

import de.huxhorn.sulky.ulid.ULID

class FakeDatacollectorRepository: DatacollectorRepository {
    override suspend fun insert(check: CheckResult): ULID.Value {
        TODO("Not yet implemented")
    }

    override suspend fun allForRepo(name: String): List<CheckResult> {
        return emptyList()
    }

    override suspend fun delete(id: ULID.Value): Int {
        return 0
    }
}