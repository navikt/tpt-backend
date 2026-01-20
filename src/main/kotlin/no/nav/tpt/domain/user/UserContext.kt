package no.nav.tpt.domain.user

data class UserContext(
    val email: String,
    val role: UserRole,
    val teams: List<String>
)
