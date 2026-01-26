package no.nav.tpt.infrastructure.teamkatalogen

class MockTeamkatalogenService : TeamkatalogenService {
    override suspend fun getMembershipByEmail(email: String): MembershipResponse {
        return MembershipResponse(
            naisTeams = listOf("appsec-a", "appsec-b"),
            clusters = emptyList(),
            productAreas = emptyList()
        )
    }

    override suspend fun getSubteamNaisTeams(
        clusters: List<TeamkatalogenEntity>,
        productAreas: List<TeamkatalogenEntity>
    ): List<String> {
        return emptyList()
    }
}

