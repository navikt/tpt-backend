package no.nav.tpt.infrastructure.teamkatalogen

class MockTeamkatalogenService : TeamkatalogenService {
    override suspend fun getMembershipByEmail(email: String): MembershipResponse {
        return MembershipResponse(
            teams = listOf(
                TeamMembership(
                    naisTeams = listOf("appsec-a", "appsec-b")
                )
            )
        )
    }
}

