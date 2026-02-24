package no.nav.tpt.infrastructure.ai

import kotlinx.coroutines.flow.Flow

interface AiClient {
    fun streamCompletion(systemPrompt: String, userPrompt: String): Flow<String>
}
