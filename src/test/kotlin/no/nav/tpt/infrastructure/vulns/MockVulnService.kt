package no.nav.tpt.infrastructure.vulns

import kotlinx.serialization.json.Json
import no.nav.tpt.domain.VulnResponse
import no.nav.tpt.domain.user.UserRole
import java.io.File

class MockVulnService : VulnService {
    private val json = Json {
        ignoreUnknownKeys = true
        isLenient = true
    }

    private val mockDataFile = File("src/test/resources/mock-vulnerabilities.json")

    override suspend fun fetchVulnerabilitiesForUser(email: String, bypassCache: Boolean): VulnResponse {
        if (!mockDataFile.exists()) {
            return VulnResponse(userRole = UserRole.DEVELOPER, teams = emptyList())
        }

        return try {
            val jsonContent = mockDataFile.readText()
            json.decodeFromString<VulnResponse>(jsonContent)
        } catch (e: Exception) {
            VulnResponse(userRole = UserRole.DEVELOPER, teams = emptyList())
        }
    }
}

