package no.nav.tpt.infrastructure.vulnrichment.utils

import no.nav.tpt.infrastructure.gcve.GcveAffectedProduct
import no.nav.tpt.infrastructure.gcve.GcveVersion
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class VersionMatcherTest {

    private fun product(
        defaultStatus: String?,
        vararg versions: GcveVersion,
    ) = GcveAffectedProduct(vendor = null, product = null, defaultStatus = defaultStatus, versions = versions.toList())

    private fun version(
        version: String,
        status: String = "affected",
        lessThan: String? = null,
        lessThanOrEqual: String? = null,
        versionType: String? = "semver",
    ) = GcveVersion(version = version, status = status, lessThan = lessThan, lessThanOrEqual = lessThanOrEqual, versionType = versionType)

    // --- parseVersion ---

    @Test
    fun `should parse simple version`() {
        assertEquals(listOf(1, 2, 3), VersionMatcher.parseVersion("1.2.3"))
    }

    @Test
    fun `should parse version with leading v`() {
        assertEquals(listOf(1, 0, 0), VersionMatcher.parseVersion("v1.0.0"))
    }

    @Test
    fun `should parse pre-release by taking only leading digits`() {
        assertEquals(listOf(11, 0, 0), VersionMatcher.parseVersion("11.0.0-M1"))
    }

    @Test
    fun `should parse zero version`() {
        assertEquals(listOf(0), VersionMatcher.parseVersion("0"))
    }

    @Test
    fun `should return null for non-numeric version`() {
        assertEquals(null, VersionMatcher.parseVersion("abc"))
    }

    // --- compareVersions ---

    @Test
    fun `should consider equal versions equal`() {
        assertEquals(0, VersionMatcher.compareVersions(listOf(1, 2, 3), listOf(1, 2, 3)))
    }

    @Test
    fun `should pad shorter version with zeros`() {
        assertEquals(0, VersionMatcher.compareVersions(listOf(1, 0), listOf(1, 0, 0)))
    }

    @Test
    fun `should correctly order versions`() {
        assertTrue(VersionMatcher.compareVersions(listOf(2, 0, 0), listOf(1, 9, 9)) > 0)
        assertTrue(VersionMatcher.compareVersions(listOf(1, 0, 0), listOf(1, 0, 1)) < 0)
    }

    // --- isNotAffected ---

    @Test
    fun `should return false for unsupported ecosystem`() {
        val products = listOf(product("unaffected", version("0", lessThanOrEqual = "0.96")))
        assertFalse(VersionMatcher.isNotAffected(products, "rpm", "0.95"))
    }

    @Test
    fun `should return false when no affected products`() {
        assertFalse(VersionMatcher.isNotAffected(emptyList(), "maven", "2.18.0"))
    }

    @Test
    fun `should return true when version is above lessThanOrEqual upper bound with defaultStatus unaffected`() {
        val products = listOf(
            product("unaffected", version("0", lessThanOrEqual = "0.96"))
        )
        assertTrue(VersionMatcher.isNotAffected(products, "maven", "1.0.0"))
    }

    @Test
    fun `should return false when version is within affected range`() {
        val products = listOf(
            product("unaffected", version("2.10.0", lessThan = "2.18.8"))
        )
        assertFalse(VersionMatcher.isNotAffected(products, "maven", "2.15.0"))
    }

    @Test
    fun `should return true when version is exactly at lessThan boundary`() {
        val products = listOf(
            product("unaffected", version("2.10.0", lessThan = "2.18.8"))
        )
        assertTrue(VersionMatcher.isNotAffected(products, "maven", "2.18.8"))
    }

    @Test
    fun `should return false when version is exactly at lessThanOrEqual boundary`() {
        val products = listOf(
            product("unaffected", version("0", lessThanOrEqual = "0.96"))
        )
        assertFalse(VersionMatcher.isNotAffected(products, "maven", "0.96"))
    }

    @Test
    fun `should return true when version is below all affected ranges with defaultStatus unaffected`() {
        val products = listOf(
            product("unaffected", version("2.10.0", lessThan = "2.18.8"))
        )
        assertTrue(VersionMatcher.isNotAffected(products, "maven", "2.9.0"))
    }

    @Test
    fun `should return false when any version range uses unknown versionType`() {
        val products = listOf(
            product("unaffected", version("0", lessThanOrEqual = "0.96", versionType = "custom"))
        )
        assertFalse(VersionMatcher.isNotAffected(products, "maven", "1.0.0"))
    }

    @Test
    fun `should return true when explicit unaffected range matches version`() {
        val products = listOf(
            product(
                defaultStatus = "affected",
                version("0", status = "unaffected", lessThan = "8.0.0"),
            )
        )
        assertTrue(VersionMatcher.isNotAffected(products, "maven", "7.9.9"))
    }

    @Test
    fun `should handle multiple affected ranges and return false if any matches`() {
        val products = listOf(
            product(
                "unaffected",
                version("2.10.0", lessThan = "2.18.8"),
                version("2.19.0", lessThan = "2.21.4"),
                version("3.0.0", lessThan = "3.1.4"),
            )
        )
        // In first range
        assertFalse(VersionMatcher.isNotAffected(products, "maven", "2.15.0"))
        // In second range
        assertFalse(VersionMatcher.isNotAffected(products, "maven", "2.20.0"))
        // In third range
        assertFalse(VersionMatcher.isNotAffected(products, "maven", "3.0.5"))
        // Above all ranges → not affected
        assertTrue(VersionMatcher.isNotAffected(products, "maven", "3.1.4"))
    }
}
