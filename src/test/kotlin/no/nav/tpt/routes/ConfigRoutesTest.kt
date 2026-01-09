package no.nav.tpt.routes

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.Json
import no.nav.tpt.domain.ConfigResponse
import no.nav.tpt.plugins.testModule
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ConfigRoutesTest {

    private val json = Json { ignoreUnknownKeys = true }

    @Test
    fun `should return config with risk thresholds`() = testApplication {
        application { testModule() }

        val response = client.get("/config")
        assertEquals(HttpStatusCode.OK, response.status)

        val responseBody = response.bodyAsText()
        val config = json.decodeFromString<ConfigResponse>(responseBody)

        assertEquals(100.0, config.thresholds.high)
        assertEquals(50.0, config.thresholds.medium)
        assertEquals(30.0, config.thresholds.low)
    }

    @Test
    fun `should return thresholds in descending order`() = testApplication {
        application { testModule() }

        val response = client.get("/config")
        val responseBody = response.bodyAsText()
        val config = json.decodeFromString<ConfigResponse>(responseBody)

        assertTrue(config.thresholds.high > config.thresholds.medium)
        assertTrue(config.thresholds.medium > config.thresholds.low)
    }

    @Test
    fun `should return valid JSON response`() = testApplication {
        application { testModule() }

        val response = client.get("/config")

        assertEquals(HttpStatusCode.OK, response.status)
        assertTrue(response.contentType()?.match(ContentType.Application.Json) == true)
    }
}

