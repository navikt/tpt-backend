package no.nav.tpt.infrastructure.teamkatalogen

class TeamkatalogenServiceImpl(
    private val client: TeamkatalogenClient
) : TeamkatalogenService {

    override suspend fun getMembershipByEmail(email: String): MembershipResponse {
        return client.getMembershipByEmail(email)
    }
}

