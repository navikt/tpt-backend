package no.nav.tpt.infrastructure.user

import no.nav.tpt.domain.user.UserContext
import no.nav.tpt.domain.user.UserContextService
import no.nav.tpt.domain.user.UserRole
import no.nav.tpt.infrastructure.nais.NaisApiService
import no.nav.tpt.infrastructure.teamkatalogen.TeamkatalogenService
import org.slf4j.LoggerFactory

class UserContextServiceImpl(
    private val naisApiService: NaisApiService,
    private val teamkatalogenService: TeamkatalogenService,
    private val adminAuthorizationService: no.nav.tpt.domain.user.AdminAuthorizationService
) : UserContextService {
    private val logger = LoggerFactory.getLogger(UserContextServiceImpl::class.java)

    override suspend fun getUserContext(email: String, groups: List<String>): UserContext {
        // Check admin status first (highest priority)
        if (adminAuthorizationService.isAdmin(groups)) {
            logger.debug("User $email is ADMIN")

            // If we cant find teams for the admin user they can still search elsewhere
            // So we return an empty list here if no teams are found
            val allTeams = getAllTeamsForUser(email)
            return UserContext(
                email = email,
                role = UserRole.ADMIN,
                teams = allTeams
            )
        }
        
        // Check NAIS team membership (second priority)
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

        // Step 3: Check if user is LEADER (clusters/productAreas with subteams containing NAIS teams)
        val allClusterIds = membershipResponse.clusterIds
        val allProductAreaIds = membershipResponse.clusterProductAreaIds + membershipResponse.productAreaIds
        
        if (allClusterIds.isNotEmpty() || allProductAreaIds.isNotEmpty()) {
            val subteamNaisTeams = teamkatalogenService.getSubteamNaisTeams(allClusterIds, allProductAreaIds)
            
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
    
    private suspend fun getAllTeamsForUser(email: String): List<String> {
        val naisTeams = naisApiService.getTeamMembershipsForUser(email)
        if (naisTeams.isNotEmpty()) {
            return naisTeams
        }
        
        val membershipResponse = teamkatalogenService.getMembershipByEmail(email)
        if (membershipResponse.naisTeams.isNotEmpty()) {
            return membershipResponse.naisTeams
        }
        
        val allClusterIds = membershipResponse.clusterIds
        val allProductAreaIds = membershipResponse.clusterProductAreaIds + membershipResponse.productAreaIds
        
        if (allClusterIds.isNotEmpty() || allProductAreaIds.isNotEmpty()) {
            return teamkatalogenService.getSubteamNaisTeams(allClusterIds, allProductAreaIds)
        }
        
        return emptyList()
    }
}
