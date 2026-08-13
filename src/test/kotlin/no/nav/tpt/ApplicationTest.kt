package no.nav.tpt

import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlin.test.*
import no.nav.tpt.plugins.testModule

class ApplicationTest {
    @Test
    fun `should return isready when calling isready endpoint`() = testApplication {
        application {
            testModule()
        }
        val response = client.get("/internal/isready")
        assertEquals(HttpStatusCode.OK, response.status)
    }

    @Test
    fun `should return isalive when calling isalive endpoint`() = testApplication {
        application {
            testModule()
        }
        val response = client.get("/internal/isalive")
        assertEquals(HttpStatusCode.OK, response.status)
    }
}

