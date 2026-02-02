package no.nav.tpt.domain.user

interface AdminAuthorizationService {
    fun isAdmin(userGroups: List<String>): Boolean
    fun getAdminGroups(): List<String>
}
