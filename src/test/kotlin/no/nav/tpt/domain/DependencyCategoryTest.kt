package no.nav.tpt.domain

import kotlin.test.Test
import kotlin.test.assertEquals

class DependencyCategoryTest {

    @Test
    fun `should classify deb as OS_PACKAGE`() {
        assertEquals(DependencyCategory.OS_PACKAGE, DependencyCategory.fromPurlType("deb"))
    }

    @Test
    fun `should classify rpm as OS_PACKAGE`() {
        assertEquals(DependencyCategory.OS_PACKAGE, DependencyCategory.fromPurlType("rpm"))
    }

    @Test
    fun `should classify apk as OS_PACKAGE`() {
        assertEquals(DependencyCategory.OS_PACKAGE, DependencyCategory.fromPurlType("apk"))
    }

    @Test
    fun `should classify apkg as OS_PACKAGE`() {
        assertEquals(DependencyCategory.OS_PACKAGE, DependencyCategory.fromPurlType("apkg"))
    }

    @Test
    fun `should classify npm as APPLICATION`() {
        assertEquals(DependencyCategory.APPLICATION, DependencyCategory.fromPurlType("npm"))
    }

    @Test
    fun `should classify maven as APPLICATION`() {
        assertEquals(DependencyCategory.APPLICATION, DependencyCategory.fromPurlType("maven"))
    }

    @Test
    fun `should classify pypi as APPLICATION`() {
        assertEquals(DependencyCategory.APPLICATION, DependencyCategory.fromPurlType("pypi"))
    }

    @Test
    fun `should classify cargo as APPLICATION`() {
        assertEquals(DependencyCategory.APPLICATION, DependencyCategory.fromPurlType("cargo"))
    }

    @Test
    fun `should classify golang as APPLICATION`() {
        assertEquals(DependencyCategory.APPLICATION, DependencyCategory.fromPurlType("golang"))
    }

    @Test
    fun `should classify gem as APPLICATION`() {
        assertEquals(DependencyCategory.APPLICATION, DependencyCategory.fromPurlType("gem"))
    }

    @Test
    fun `should classify nuget as APPLICATION`() {
        assertEquals(DependencyCategory.APPLICATION, DependencyCategory.fromPurlType("nuget"))
    }

    @Test
    fun `should classify docker as CONTAINER`() {
        assertEquals(DependencyCategory.CONTAINER, DependencyCategory.fromPurlType("docker"))
    }

    @Test
    fun `should classify oci as CONTAINER`() {
        assertEquals(DependencyCategory.CONTAINER, DependencyCategory.fromPurlType("oci"))
    }

    @Test
    fun `should return UNKNOWN for null type`() {
        assertEquals(DependencyCategory.UNKNOWN, DependencyCategory.fromPurlType(null))
    }

    @Test
    fun `should return UNKNOWN for unrecognized type`() {
        assertEquals(DependencyCategory.UNKNOWN, DependencyCategory.fromPurlType("unknown-type"))
    }

    @Test
    fun `should be case insensitive`() {
        assertEquals(DependencyCategory.OS_PACKAGE, DependencyCategory.fromPurlType("DEB"))
        assertEquals(DependencyCategory.APPLICATION, DependencyCategory.fromPurlType("NPM"))
        assertEquals(DependencyCategory.CONTAINER, DependencyCategory.fromPurlType("Docker"))
    }
}
