package no.nav.tpt.infrastructure.user

import no.nav.tpt.domain.user.UserContext
import no.nav.tpt.domain.user.UserContextService
import no.nav.tpt.domain.user.UserRole
import no.nav.tpt.infrastructure.nais.NaisApiService
import no.nav.tpt.infrastructure.teamkatalogen.TeamkatalogenService

class UserContextServiceImpl(
    private val naisApiService: NaisApiService,
    private val teamkatalogenService: TeamkatalogenService
) : UserContextService {

    override suspend fun getUserContext(email: String): UserContext {
        var role = UserRole.NONE
        val naisTeams = naisApiService.getTeamMembershipsForUser(email)

        val teams = if(naisTeams.isEmpty()) {
            // Check is user is a member of any team in Teamkatalogen that has a Nais team
            // If so the user is a team member.
            val membershipResponse = teamkatalogenService.getMembershipByEmail(email)
            if(membershipResponse.naisTeams.isNotEmpty()) {
                role = UserRole.TEAM_MEMBER
            }
            membershipResponse.naisTeams
        } else {
            // If Nais says the user belongs to nais teams the user is considered a developer
            role = UserRole.DEVELOPER
            naisTeams
        }

        return UserContext(
            email = email,
            role = role,
            teams = teams
        )
    }
}
