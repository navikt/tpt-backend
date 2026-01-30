package no.nav.tpt.infrastructure.vulns.utils

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class PurlParserTest {

    @Test
    fun `should extract name from simple PURL without namespace`() {
        val purl = "pkg:npm/foobar@12.3.1"
        assertEquals("foobar", PurlParser.extractPackageName(purl))
    }

    @Test
    fun `should extract name from PURL with namespace`() {
        val purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
        assertEquals("log4j-core", PurlParser.extractPackageName(purl))
    }

    @Test
    fun `should extract name from PURL with multiple namespace segments`() {
        val purl = "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?packaging=sources"
        assertEquals("batik-anim", PurlParser.extractPackageName(purl))
    }

    @Test
    fun `should extract name from Debian PURL`() {
        val purl = "pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie"
        assertEquals("curl", PurlParser.extractPackageName(purl))
    }

    @Test
    fun `should extract name from Docker PURL with namespace`() {
        val purl = "pkg:docker/cassandra@sha256:244fd47e07d1004f0aed9c"
        assertEquals("cassandra", PurlParser.extractPackageName(purl))
    }

    @Test
    fun `should extract name from PyPI PURL`() {
        val purl = "pkg:pypi/django@1.11.1"
        assertEquals("django", PurlParser.extractPackageName(purl))
    }

    @Test
    fun `should extract name from PURL without version`() {
        val purl = "pkg:npm/foobar"
        assertEquals("foobar", PurlParser.extractPackageName(purl))
    }

    @Test
    fun `should extract name from PURL with qualifiers but no version`() {
        val purl = "pkg:deb/debian/curl?arch=i386"
        assertEquals("curl", PurlParser.extractPackageName(purl))
    }

    @Test
    fun `should extract name from PURL with subpath`() {
        val purl = "pkg:npm/%40angular/core@1.0.0#src/utils"
        assertEquals("@angular/core", PurlParser.extractPackageName(purl))
    }

    @Test
    fun `should handle PURL with leading slashes after scheme`() {
        val purl = "pkg://npm/foobar@12.3.1"
        assertEquals("foobar", PurlParser.extractPackageName(purl))
    }

    @Test
    fun `should handle percent-encoded name`() {
        val purl = "pkg:npm/foo%2Fbar@1.0.0"
        assertEquals("foo/bar", PurlParser.extractPackageName(purl))
    }

    @Test
    fun `should return null for null input`() {
        assertNull(PurlParser.extractPackageName(null))
    }

    @Test
    fun `should return null for blank input`() {
        assertNull(PurlParser.extractPackageName(""))
        assertNull(PurlParser.extractPackageName("   "))
    }

    @Test
    fun `should return null for non-PURL string`() {
        assertNull(PurlParser.extractPackageName("https://github.com/owner/repo"))
    }

    @Test
    fun `should return null for invalid PURL without name`() {
        assertNull(PurlParser.extractPackageName("pkg:npm"))
    }

    @Test
    fun `should handle complex Maven PURL with groupId`() {
        val purl = "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0"
        assertEquals("jackson-databind", PurlParser.extractPackageName(purl))
    }

    @Test
    fun `should handle npm scoped package`() {
        val purl = "pkg:npm/%40types/node@16.0.0"
        assertEquals("@types/node", PurlParser.extractPackageName(purl))
    }

    @Test
    fun `should extract name ignoring version and qualifiers`() {
        val purl = "pkg:gem/ruby-advisory-db-check@0.12.4?arch=x86_64"
        assertEquals("ruby-advisory-db-check", PurlParser.extractPackageName(purl))
    }

    @Test
    fun `should handle PURL with complex version containing special chars`() {
        val purl = "pkg:deb/ubuntu/nginx@1.18.0-0ubuntu1.2"
        assertEquals("nginx", PurlParser.extractPackageName(purl))
    }

    @Test
    fun `should handle cargo PURL`() {
        val purl = "pkg:cargo/rand@0.7.2"
        assertEquals("rand", PurlParser.extractPackageName(purl))
    }

    @Test
    fun `should handle golang PURL with namespace`() {
        val purl = "pkg:golang/github.com/gorilla/mux@1.8.0"
        assertEquals("mux", PurlParser.extractPackageName(purl))
    }
}

