package no.nav.tpt.domain.user

interface UserContextService {
    suspend fun getUserContext(email: String, groups: List<String> = emptyList()): UserContext
}
