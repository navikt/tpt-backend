package no.nav.tpt.infrastructure.teamkatalogen

class MockTeamkatalogenService : TeamkatalogenService {
    override suspend fun getMembershipByEmail(email: String): MembershipResponse {
        return MembershipResponse(
            naisTeams = listOf("appsec-a", "appsec-b"),
            clusterIds = emptyList(),
            clusterProductAreaIds = emptyList(),
            productAreaIds = emptyList()
        )
    }

    override suspend fun getSubteamNaisTeams(clusterIds: List<String>, productAreaIds: List<String>): List<String> {
        return emptyList()
    }
}

