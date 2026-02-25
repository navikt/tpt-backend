package no.nav.tpt.infrastructure.ai

import kotlinx.serialization.Serializable

@Serializable
data class GeminiChatRequest(
    val contents: List<GeminiContent>,
    val systemInstruction: GeminiSystemInstruction? = null,
    val generationConfig: GeminiGenerationConfig? = null
)

@Serializable
data class GeminiContent(
    val role: String,
    val parts: List<GeminiPart>
)

@Serializable
data class GeminiPart(
    val text: String
)

@Serializable
data class GeminiSystemInstruction(
    val parts: List<GeminiPart>
)

// https://docs.cloud.google.com/vertex-ai/generative-ai/docs/reference/rest/v1/GenerationConfig
@Serializable
data class GeminiGenerationConfig(
    val maxOutputTokens: Int = 8192
)

@Serializable
data class GeminiStreamEvent(
    val candidates: List<GeminiCandidate>? = null
)

// https://cloud.google.com/vertex-ai/generative-ai/docs/reference/rest/v1/GenerateContentResponse#FinishReason
@Serializable
data class GeminiCandidate(
    val content: GeminiContent? = null,
    val finishReason: String? = null
)
