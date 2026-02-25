package no.nav.tpt.infrastructure.ai

import com.google.auth.oauth2.GoogleCredentials
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.utils.io.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory

private val logger = LoggerFactory.getLogger(GeminiVertexAiClient::class.java)

class GeminiVertexAiClient(
    private val httpClient: HttpClient,
    private val apiBaseUrl: String,
    private val model: String = "gemini-2.5-flash"
) : AiClient {

    private val json = Json { ignoreUnknownKeys = true }

    private val credentials: GoogleCredentials = GoogleCredentials
        .getApplicationDefault()
        .createScoped("https://www.googleapis.com/auth/cloud-platform")

    private suspend fun accessToken(): String = withContext(Dispatchers.IO) {
        credentials.refreshIfExpired()
        credentials.accessToken.tokenValue
    }

    override fun streamCompletion(systemPrompt: String, userPrompt: String): Flow<String> = channelFlow {
        val token = accessToken()
        val url = "$apiBaseUrl/$model:streamGenerateContent?alt=sse"

        val request = GeminiChatRequest(
            contents = listOf(GeminiContent(role = "user", parts = listOf(GeminiPart(userPrompt)))),
            systemInstruction = GeminiSystemInstruction(parts = listOf(GeminiPart(systemPrompt))),
            generationConfig = GeminiGenerationConfig(maxOutputTokens = 1024)
        )

        httpClient.preparePost(url) {
            contentType(ContentType.Application.Json)
            header(HttpHeaders.Authorization, "Bearer $token")
            setBody(request)
        }.execute { response ->
            if (!response.status.isSuccess()) {
                val errorBody = response.bodyAsText()
                throw Exception("Vertex AI returned ${response.status.value}: $errorBody")
            }
            val channel = response.bodyAsChannel()
            var finishReason: String? = null
            while (!channel.isClosedForRead) {
                val line = channel.readLine() ?: break
                if (!line.startsWith("data: ")) continue
                val data = line.removePrefix("data: ")
                try {
                    val event = json.decodeFromString<GeminiStreamEvent>(data)
                    val candidate = event.candidates?.firstOrNull()
                    candidate?.content?.parts?.forEach { part ->
                        if (part.text.isNotEmpty()) send(part.text)
                    }
                    if (candidate?.finishReason != null) finishReason = candidate.finishReason
                } catch (e: SerializationException) {
                    logger.warn("Failed to parse Gemini SSE event, skipping: $data", e)
                }
            }
            if (finishReason != null && finishReason != "STOP") {
                throw Exception("Gemini stream ended with finishReason=$finishReason — response may be incomplete")
            }
        }
    }
}
