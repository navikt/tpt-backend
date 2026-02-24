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

@Serializable
data class GeminiGenerationConfig(
    val maxOutputTokens: Int = 1024
)

@Serializable
data class GeminiStreamEvent(
    val candidates: List<GeminiCandidate>? = null
)

@Serializable
data class GeminiCandidate(
    val content: GeminiContent? = null
)
