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
import org.junit.jupiter.api.Assertions.assertTrue

class DataCollectorTest {

    @Test
    fun `Loads data from tpt-data-collector using bearer auth`() = runTest {
        val mockEngine = MockEngine { req ->
            respond(
                content = if (req.url.encodedPath.contains("token")) {
                    tokenResponse
                } else {
                    dataResponse
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

        val dataCollector = RealDataCollector(naisTokenEndpoint = "http://localhost:8080/token", httpClient = httpClient)
        val checkResults = dataCollector.collectDataFor("tulleteam")

        assertTrue { checkResults.isNotEmpty() }
    }

}

val tokenResponse = """
    {
        "access_token": "eyJra...",
        "expires_in": 3599,
        "token_type": "Bearer"
    }
""".trimIndent()

val dataResponse = """
    [
        {
            "type": "no.nav.tpt.infrastructure.datacollector.CheckResult.AllGood",
            "name": "TulleCheck",
            "repo": "tullerepo",
            "whenChecked": "2026-07-29T08:49:43.931831Z"
        },
        {
            "type": "no.nav.tpt.infrastructure.datacollector.CheckResult.NeedsWork",
            "name": "YoloCheck",
            "repo": "yolorepo",
            "whenChecked": "2026-07-29T08:49:43.932327Z",
            "reasons": [
                "It has issues"
            ]
        }
    ]
""".trimIndent()