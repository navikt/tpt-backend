package no.nav.tpt.domain.user

class MockUserContextService(
    private val mockRole: UserRole = UserRole.DEVELOPER,
    private val mockTeams: List<String> = emptyList()
) : UserContextService {

    override suspend fun getUserContext(email: String): UserContext {
        return UserContext(
            email = email,
            role = mockRole,
            teams = mockTeams
        )
    }
}
