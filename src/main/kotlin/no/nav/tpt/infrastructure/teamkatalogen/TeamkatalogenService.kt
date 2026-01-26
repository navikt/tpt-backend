package no.nav.tpt.infrastructure.teamkatalogen

interface TeamkatalogenService {
    suspend fun getMembershipByEmail(email: String): MembershipResponse
    suspend fun getSubteamNaisTeams(productAreaIds: List<String>): List<String>
}

