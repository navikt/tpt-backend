package no.nav.tpt.infrastructure.vulnrichment.utils

import no.nav.tpt.infrastructure.gcve.GcveAffectedProduct
import no.nav.tpt.infrastructure.gcve.GcveVersion

object VersionMatcher {

    private val SUPPORTED_ECOSYSTEMS = setOf("maven", "npm", "pypi", "golang", "nuget")

    private val SUPPORTED_VERSION_TYPES = setOf("semver", "maven", "npm", "python", "generic")

    fun isNotAffected(
        affectedProducts: List<GcveAffectedProduct>,
        packageType: String,
        packageVersion: String,
    ): Boolean {
        if (packageType !in SUPPORTED_ECOSYSTEMS) return false
        if (affectedProducts.isEmpty()) return false

        val parsed = parseVersion(packageVersion) ?: return false

        return affectedProducts.any { product ->
            isProductNotAffected(product, parsed)
        }
    }

    private fun isProductNotAffected(product: GcveAffectedProduct, version: List<Int>): Boolean {
        val versions = product.versions

        // If any version range has an unsupported versionType, skip this product — be conservative
        if (versions.any { it.versionType != null && it.versionType !in SUPPORTED_VERSION_TYPES }) {
            return false
        }

        // Check for an explicit "unaffected" range that matches our version
        val explicitlyUnaffected = versions.any { v ->
            v.status == "unaffected" && matchesRange(version, v)
        }
        if (explicitlyUnaffected) return true

        // If defaultStatus is "unaffected", check that version doesn't match any "affected" range
        if (product.defaultStatus == "unaffected") {
            val matchesAffected = versions.any { v ->
                v.status == "affected" && matchesRange(version, v)
            }
            return !matchesAffected
        }

        return false
    }

    private fun matchesRange(version: List<Int>, range: GcveVersion): Boolean {
        val lower = range.version?.let { parseVersion(it) }
        val upper = when {
            range.lessThan != null -> parseVersion(range.lessThan)
            range.lessThanOrEqual != null -> parseVersion(range.lessThanOrEqual)
            else -> null
        }

        if (lower == null && upper == null) return false

        val aboveLower = lower == null || compareVersions(version, lower) >= 0
        val belowUpper = when {
            range.lessThan != null && upper != null -> compareVersions(version, upper) < 0
            range.lessThanOrEqual != null && upper != null -> compareVersions(version, upper) <= 0
            else -> true
        }

        return aboveLower && belowUpper
    }

    internal fun parseVersion(version: String): List<Int>? {
        val cleaned = version.trimStart('v', 'V')
        if (cleaned.isBlank() || cleaned == "0") return listOf(0)
        val parts = cleaned.split('.')
        val ints = parts.map { part ->
            // Take only leading digits (handles pre-release like "11.0.0-M1")
            val digits = part.takeWhile { it.isDigit() }
            digits.toIntOrNull() ?: return null
        }
        return ints.ifEmpty { null }
    }

    internal fun compareVersions(a: List<Int>, b: List<Int>): Int {
        val len = maxOf(a.size, b.size)
        for (i in 0 until len) {
            val ai = a.getOrElse(i) { 0 }
            val bi = b.getOrElse(i) { 0 }
            if (ai != bi) return ai.compareTo(bi)
        }
        return 0
    }
}
