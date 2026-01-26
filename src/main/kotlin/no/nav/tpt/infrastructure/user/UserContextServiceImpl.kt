package no.nav.tpt.infrastructure.user

import no.nav.tpt.domain.user.UserContext
import no.nav.tpt.domain.user.UserContextService
import no.nav.tpt.domain.user.UserRole
import no.nav.tpt.infrastructure.nais.NaisApiService
import no.nav.tpt.infrastructure.teamkatalogen.TeamkatalogenService
import org.slf4j.LoggerFactory

class UserContextServiceImpl(
    private val naisApiService: NaisApiService,
    private val teamkatalogenService: TeamkatalogenService
) : UserContextService {
    private val logger = LoggerFactory.getLogger(UserContextServiceImpl::class.java)

    override suspend fun getUserContext(email: String): UserContext {
        // Check NAIS team membership first (highest priority)
        val naisTeams = naisApiService.getTeamMembershipsForUser(email)
        
        if (naisTeams.isNotEmpty()) {
            logger.debug("User $email is DEVELOPER with ${naisTeams.size} NAIS teams")
            return UserContext(
                email = email,
                role = UserRole.DEVELOPER,
                teams = naisTeams
            )
        }

        // User has no direct NAIS membership, check Teamkatalogen
        val membershipResponse = teamkatalogenService.getMembershipByEmail(email)
        
        // Check if user has direct teams with naisTeams (TEAM_MEMBER)
        if (membershipResponse.naisTeams.isNotEmpty()) {
            logger.debug("User $email is TEAM_MEMBER with ${membershipResponse.naisTeams.size} teams")
            return UserContext(
                email = email,
                role = UserRole.TEAM_MEMBER,
                teams = membershipResponse.naisTeams
            )
        }

        // Step 3: Check if user is LEADER (productAreas with subteams containing NAIS teams)
        val allProductAreaIds = membershipResponse.clusterProductAreaIds + membershipResponse.productAreaIds
        if (allProductAreaIds.isNotEmpty()) {
            val subteamNaisTeams = teamkatalogenService.getSubteamNaisTeams(allProductAreaIds)
            
            if (subteamNaisTeams.isNotEmpty()) {
                logger.debug("User $email is LEADER with ${subteamNaisTeams.size} subteam NAIS teams")
                return UserContext(
                    email = email,
                    role = UserRole.LEADER,
                    teams = subteamNaisTeams
                )
            }
        }

        // No affiliation found
        logger.debug("User $email has no team affiliation (NONE)")
        return UserContext(
            email = email,
            role = UserRole.NONE,
            teams = emptyList()
        )
    }
}
