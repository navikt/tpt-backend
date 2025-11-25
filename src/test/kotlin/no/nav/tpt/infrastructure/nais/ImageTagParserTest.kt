package no.nav.tpt.infrastructure.nais

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import java.time.LocalDate

class ImageTagParserTest {

    @Test
    fun `should extract build date from tag with dash separator format`() {
        val imageTag = "2025.11.20-06.22-4c8872c"
        val result = ImageTagParser.extractBuildDate(imageTag)

        assertEquals(LocalDate.of(2025, 11, 20), result)
    }

    @Test
    fun `should extract build date from tag with underscore separator format`() {
        val imageTag = "2025.11.06_14.11-720172dff35e"
        val result = ImageTagParser.extractBuildDate(imageTag)

        assertEquals(LocalDate.of(2025, 11, 6), result)
    }

    @Test
    fun `should extract build date from tag with compact timestamp format`() {
        val imageTag = "2025.11.24.123317-4358930"
        val result = ImageTagParser.extractBuildDate(imageTag)

        assertEquals(LocalDate.of(2025, 11, 24), result)
    }

    @Test
    fun `should return null for invalid tag format`() {
        val imageTag = "latest"
        val result = ImageTagParser.extractBuildDate(imageTag)

        assertNull(result)
    }

    @Test
    fun `should return null for malformed timestamp`() {
        val imageTag = "invalid-timestamp-format"
        val result = ImageTagParser.extractBuildDate(imageTag)

        assertNull(result)
    }
}

