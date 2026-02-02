package no.nav.tpt.infrastructure.user

import no.nav.tpt.domain.user.AdminAuthorizationService
import org.slf4j.LoggerFactory

class AdminAuthorizationServiceImpl(adminGroupsConfig: String? = System.getenv("ADMIN_GROUPS")) : AdminAuthorizationService {
    private val logger = LoggerFactory.getLogger(AdminAuthorizationServiceImpl::class.java)
    private val adminGroups: List<String>

    init {
        val adminGroupsEnv = adminGroupsConfig ?: ""
        adminGroups = adminGroupsEnv.split(",")
            .map { it.trim() }
            .filter { it.isNotEmpty() }
        logger.info("Configured ${adminGroups.size} admin groups")
    }

    override fun isAdmin(userGroups: List<String>): Boolean {
        if (adminGroups.isEmpty()) {
            logger.debug("No admin groups configured")
            return false
        }
        
        val isAdmin = userGroups.any { it in adminGroups }
        logger.debug("Admin check: user has ${userGroups.size} groups, is admin: $isAdmin")
        return isAdmin
    }

    override fun getAdminGroups(): List<String> = adminGroups
}
