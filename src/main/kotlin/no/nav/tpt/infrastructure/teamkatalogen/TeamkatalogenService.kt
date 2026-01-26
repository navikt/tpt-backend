package no.nav.tpt.infrastructure.teamkatalogen

interface TeamkatalogenService {
    suspend fun getMembershipByEmail(email: String): MembershipResponse
    suspend fun getSubteamNaisTeams(clusters: List<TeamkatalogenEntity>, productAreas: List<TeamkatalogenEntity>): List<String>
}

