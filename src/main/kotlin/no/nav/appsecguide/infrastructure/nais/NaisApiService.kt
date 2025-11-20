package no.nav.appsecguide.infrastructure.nais

interface NaisApiService {
    suspend fun getTeamIngressTypes(teamSlug: String): TeamIngressTypesResponse
    suspend fun getApplicationsForUser(email: String): ApplicationsForUserResponse
}

