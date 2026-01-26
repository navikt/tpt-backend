package no.nav.tpt.infrastructure.cisa

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*

open class KevClient(
    private val httpClient: HttpClient,
    private val kevUrl: String = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
) : KevService {

    override suspend fun getKevCatalog(): KevCatalog {
        val response = httpClient.get(kevUrl) {
            contentType(ContentType.Application.Json)
        }
        return response.body()
    }
}

