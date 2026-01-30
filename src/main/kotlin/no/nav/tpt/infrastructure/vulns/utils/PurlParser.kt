package no.nav.tpt.infrastructure.vulns.utils

import java.net.URLDecoder
import java.nio.charset.StandardCharsets

object PurlParser {
    fun extractPackageName(purl: String?): String? {
        if (purl.isNullOrBlank()) return null
        if (!purl.startsWith("pkg:")) return null

        val withoutScheme = purl.substringAfter("pkg:")
            .trimStart('/')

        val pathPart = withoutScheme
            .substringBefore('?')
            .substringBefore('#')

        val segments = pathPart.split('/')
        if (segments.size < 2) return null

        val type = segments.first()

        val namespaceAndName = segments.drop(1)
        if (namespaceAndName.isEmpty()) return null

        val packageIdentifier = if (type.equals("npm", ignoreCase = true) && namespaceAndName.size > 1) {
            namespaceAndName.joinToString("/")
        } else {
            namespaceAndName.last()
        }

        if (packageIdentifier.isBlank()) return null

        val lastAtIndex = packageIdentifier.lastIndexOf('@')
        val nameOnly = if (lastAtIndex > 0) {
            packageIdentifier.substring(0, lastAtIndex)
        } else {
            packageIdentifier
        }

        return percentDecode(nameOnly).takeIf { it.isNotBlank() }
    }

    private fun percentDecode(value: String): String {
        return try {
            URLDecoder.decode(value, StandardCharsets.UTF_8.name())
        } catch (e: Exception) {
            value
        }
    }
}