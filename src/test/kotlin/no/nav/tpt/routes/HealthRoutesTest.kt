package no.nav.tpt.routes

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.testing.*
import no.nav.tpt.plugins.testModule
import kotlin.test.Test
import kotlin.test.assertEquals

class HealthRoutesTest {

    @Test
    fun `should return OK for isalive`() = testApplication {
        application { testModule() }

        val response = client.get("/isalive")
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("A-OK", response.bodyAsText())
    }

    @Test
    fun `should return OK for isready when Kafka is not configured`() = testApplication {
        application { testModule() }

        val response = client.get("/isready")
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("KIROV REPORTING", response.bodyAsText())
    }
}

