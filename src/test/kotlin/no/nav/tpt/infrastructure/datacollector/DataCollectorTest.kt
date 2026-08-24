package no.nav.tpt.infrastructure.datacollector

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.serialization.kotlinx.json.json
import kotlin.test.Test
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.assertDoesNotThrow

class DataCollectorTest {

    @Test
    fun `Loads data from tpt-data-collector using bearer auth`() = runTest {
        val mockEngine = MockEngine { req ->
            respond(
                content = if (req.url.encodedPath.contains("token")) {
                    tokenResponse
                } else {
                    ""
                },
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val dataCollector = RealDataCollector(naisTokenEndpoint = "http://localhost:8080/token", httpClient = httpClient, storage = FakeDatacollectorRepository())
        assertDoesNotThrow { dataCollector.startCollectingDataFor(listOf("tulleteam")) }
    }

}

val tokenResponse = """
    {
        "access_token": "eyJra...",
        "expires_in": 3599,
        "token_type": "Bearer"
    }
""".trimIndent()
