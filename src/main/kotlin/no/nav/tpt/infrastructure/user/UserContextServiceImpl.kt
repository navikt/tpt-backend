package no.nav.tpt.infrastructure.user

import no.nav.tpt.domain.user.UserContext
import no.nav.tpt.domain.user.UserContextService
import no.nav.tpt.domain.user.UserRole
import no.nav.tpt.infrastructure.nais.NaisApiService
import no.nav.tpt.infrastructure.teamkatalogen.TeamkatalogenService
import org.slf4j.LoggerFactory
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

class UserContextServiceImpl(
    private val naisApiService: NaisApiService,
    private val teamkatalogenService: TeamkatalogenService,
    private val adminAuthorizationService: no.nav.tpt.domain.user.AdminAuthorizationService,
    private val cacheTtlSeconds: Long = 300,
) : UserContextService {
    private val logger = LoggerFactory.getLogger(UserContextServiceImpl::class.java)

    private data class CacheEntry(val context: UserContext, val expiresAt: Instant)

    private val cache = ConcurrentHashMap<String, CacheEntry>()

    override suspend fun getUserContext(email: String, groups: List<String>): UserContext {
        val isAdmin = adminAuthorizationService.isAdmin(groups)
        val cacheKey = "$email:$isAdmin"
        val cached = cache[cacheKey]
        if (cached != null && Instant.now().isBefore(cached.expiresAt)) {
            logger.debug("UserContext cache hit for $email (role=${cached.context.role})")
            return cached.context
        }

        val context = resolveUserContext(email, groups)
        cache[cacheKey] = CacheEntry(context, Instant.now().plusSeconds(cacheTtlSeconds))
        return context
    }

    private suspend fun resolveUserContext(email: String, groups: List<String>): UserContext {
        if (adminAuthorizationService.isAdmin(groups)) {
            logger.debug("User $email is ADMIN")
            val allTeams = getAllTeamsForUser(email)
            return UserContext(
                email = email,
                role = UserRole.ADMIN,
                teams = allTeams,
            )
        }

        val naisTeams = naisApiService.getTeamMembershipsForUser(email)

        if (naisTeams.isNotEmpty()) {
            logger.debug("User $email is DEVELOPER with ${naisTeams.size} NAIS teams")
            return UserContext(
                email = email,
                role = UserRole.DEVELOPER,
                teams = naisTeams,
            )
        }

        val membershipResponse = teamkatalogenService.getMembershipByEmail(email)

        if (membershipResponse.naisTeams.isNotEmpty()) {
            logger.debug("User $email is TEAM_MEMBER with ${membershipResponse.naisTeams.size} teams")
            return UserContext(
                email = email,
                role = UserRole.TEAM_MEMBER,
                teams = membershipResponse.naisTeams,
            )
        }

        val allClusterIds = membershipResponse.clusterIds
        val allProductAreaIds = membershipResponse.clusterProductAreaIds + membershipResponse.productAreaIds

        if (allClusterIds.isNotEmpty() || allProductAreaIds.isNotEmpty()) {
            val subteamNaisTeams = teamkatalogenService.getSubteamNaisTeams(allClusterIds, allProductAreaIds)

            if (subteamNaisTeams.isNotEmpty()) {
                logger.debug("User $email is LEADER with ${subteamNaisTeams.size} subteam NAIS teams")
                return UserContext(
                    email = email,
                    role = UserRole.LEADER,
                    teams = subteamNaisTeams,
                )
            }
        }

        logger.debug("User $email has no team affiliation (NONE)")
        return UserContext(
            email = email,
            role = UserRole.NONE,
            teams = emptyList(),
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
