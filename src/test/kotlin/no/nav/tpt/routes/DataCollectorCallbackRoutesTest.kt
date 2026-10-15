package no.nav.tpt.routes

import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.JsonPrimitive
import no.nav.tpt.infrastructure.auth.IntrospectionResponse
import no.nav.tpt.infrastructure.auth.MockTokenIntrospectionService
import no.nav.tpt.infrastructure.auth.TokenIntrospectionService
import no.nav.tpt.plugins.testModule
import kotlin.test.Test
import kotlin.test.assertEquals

class DataCollectorCallbackRoutesTest {

    private val repositoryPayload = """
        {"nameWithOwner": "navikt/app", "naisTeams": ["team-a"], "vulnerabilities": []}
    """.trimIndent()

    private val checksPayload = """
        {"repoName": "navikt/app", "repoOwners": ["team-a"], "results": []}
    """.trimIndent()

    private fun appToken(claims: Map<String, String>) = object : TokenIntrospectionService {
        override suspend fun introspect(token: String) =
            IntrospectionResponse(active = true, claims = claims.mapValues { JsonPrimitive(it.value) })
    }

    private val dataCollectorToken = appToken(
        mapOf("idtyp" to "app", "azp_name" to "dev-gcp:appsec:tpt-data-collector")
    )

    @Test
    fun `should return 401 when no authorization header provided`() = testApplication {
        application { testModule(tokenIntrospectionService = dataCollectorToken) }

        val response = client.post("/callbacks/github/vulnerabilities") {
            contentType(ContentType.Application.Json)
            setBody(repositoryPayload)
        }

        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `should return 401 when token is not active`() = testApplication {
        application { testModule(tokenIntrospectionService = MockTokenIntrospectionService(shouldSucceed = false)) }

        val response = client.post("/callbacks/checks") {
            header(HttpHeaders.Authorization, "Bearer inactive")
            contentType(ContentType.Application.Json)
            setBody(checksPayload)
        }

        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `should return 401 when token belongs to a user`() = testApplication {
        application { testModule(tokenIntrospectionService = MockTokenIntrospectionService()) }

        val response = client.post("/callbacks/github/vulnerabilities") {
            header(HttpHeaders.Authorization, "Bearer user-token")
            contentType(ContentType.Application.Json)
            setBody(repositoryPayload)
        }

        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `should return 401 when token is not a machine-to-machine token`() = testApplication {
        val delegatedToken = appToken(mapOf("azp_name" to "dev-gcp:appsec:tpt-data-collector"))
        application { testModule(tokenIntrospectionService = delegatedToken) }

        val response = client.post("/callbacks/checks") {
            header(HttpHeaders.Authorization, "Bearer delegated")
            contentType(ContentType.Application.Json)
            setBody(checksPayload)
        }

        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `should return 401 when token is from a different application`() = testApplication {
        val frontendToken = appToken(mapOf("idtyp" to "app", "azp_name" to "dev-gcp:appsec:tpt-frontend"))
        application { testModule(tokenIntrospectionService = frontendToken) }

        val response = client.post("/callbacks/github/vulnerabilities") {
            header(HttpHeaders.Authorization, "Bearer frontend")
            contentType(ContentType.Application.Json)
            setBody(repositoryPayload)
        }

        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `should return 204 when data collector posts vulnerability data`() = testApplication {
        application { testModule(tokenIntrospectionService = dataCollectorToken) }

        val response = client.post("/callbacks/github/vulnerabilities") {
            header(HttpHeaders.Authorization, "Bearer data-collector")
            contentType(ContentType.Application.Json)
            setBody(repositoryPayload)
        }

        assertEquals(HttpStatusCode.NoContent, response.status)
    }

    @Test
    fun `should return 204 when data collector posts check results`() = testApplication {
        application { testModule(tokenIntrospectionService = dataCollectorToken) }

        val response = client.post("/callbacks/checks") {
            header(HttpHeaders.Authorization, "Bearer data-collector")
            contentType(ContentType.Application.Json)
            setBody(checksPayload)
        }

        assertEquals(HttpStatusCode.NoContent, response.status)
    }

    @Test
    fun `should return 400 when required fields are missing`() = testApplication {
        application { testModule(tokenIntrospectionService = dataCollectorToken) }

        val response = client.post("/callbacks/github/vulnerabilities") {
            header(HttpHeaders.Authorization, "Bearer data-collector")
            contentType(ContentType.Application.Json)
            setBody("""{"nameWithOwner": "navikt/app", "vulnerabilities": []}""")
        }

        assertEquals(HttpStatusCode.BadRequest, response.status)
    }

    @Test
    fun `should return 400 when repository name is blank`() = testApplication {
        application { testModule(tokenIntrospectionService = dataCollectorToken) }

        val response = client.post("/callbacks/checks") {
            header(HttpHeaders.Authorization, "Bearer data-collector")
            contentType(ContentType.Application.Json)
            setBody("""{"repoName": " ", "repoOwners": ["team-a"], "results": []}""")
        }

        assertEquals(HttpStatusCode.BadRequest, response.status)
    }
}
