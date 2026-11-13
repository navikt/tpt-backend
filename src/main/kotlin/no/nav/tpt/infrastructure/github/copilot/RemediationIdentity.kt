package no.nav.tpt.infrastructure.github.copilot

import java.net.URLDecoder
import java.nio.charset.StandardCharsets

object RemediationIdentity {
    private val REPOSITORY_PREFIXES = listOf("https://", "http://", "git@", "www.", "github.com/", "github.com:")

    fun normalizeRepository(value: String): String {
        var result = value.trim()
        for (prefix in REPOSITORY_PREFIXES) {
            if (result.startsWith(prefix, ignoreCase = true)) result = result.substring(prefix.length)
        }
        return result.trimEnd('/').removeSuffix(".git")
    }

    /**
     * Version-independent package identity shared by GitHub coordinates (`org.example:library`, `@scope/name`)
     * and Nais PURLs (`pkg:maven/org.example/library@1.2.3`), so both sources deduplicate to the same key.
     */
    fun packageIdentity(packageName: String?): String {
        val value = packageName?.trim().orEmpty()
        if (!value.startsWith("pkg:")) return value.lowercase()

        val path = value.removePrefix("pkg:").trimStart('/').substringBefore('?').substringBefore('#')
        val segments = path.split('/').filter { it.isNotEmpty() }
        if (segments.size < 2) return value.lowercase()

        val type = segments.first().lowercase()
        val namespace = segments.subList(1, segments.size - 1).map(::decode)
        val name = decode(segments.last().substringBeforeLast('@'))
        val identity = when {
            type == "maven" && namespace.isNotEmpty() -> "${namespace.joinToString(".")}:$name"
            else -> (namespace + name).joinToString("/")
        }
        return identity.lowercase()
    }

    private fun decode(value: String): String =
        runCatching { URLDecoder.decode(value, StandardCharsets.UTF_8) }.getOrDefault(value)
}
