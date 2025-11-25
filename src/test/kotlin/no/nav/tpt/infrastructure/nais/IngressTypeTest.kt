package no.nav.tpt.infrastructure.nais

import kotlin.test.Test
import kotlin.test.assertEquals

class IngressTypeTest {

    @Test
    fun `should parse EXTERNAL from string`() {
        assertEquals(IngressType.EXTERNAL, IngressType.fromString("external"))
        assertEquals(IngressType.EXTERNAL, IngressType.fromString("EXTERNAL"))
        assertEquals(IngressType.EXTERNAL, IngressType.fromString("External"))
    }

    @Test
    fun `should parse INTERNAL from string`() {
        assertEquals(IngressType.INTERNAL, IngressType.fromString("internal"))
        assertEquals(IngressType.INTERNAL, IngressType.fromString("INTERNAL"))
    }

    @Test
    fun `should parse AUTHENTICATED from string`() {
        assertEquals(IngressType.AUTHENTICATED, IngressType.fromString("authenticated"))
        assertEquals(IngressType.AUTHENTICATED, IngressType.fromString("AUTHENTICATED"))
    }

    @Test
    fun `should return UNKNOWN for invalid strings`() {
        assertEquals(IngressType.UNKNOWN, IngressType.fromString("invalid"))
        assertEquals(IngressType.UNKNOWN, IngressType.fromString(""))
        assertEquals(IngressType.UNKNOWN, IngressType.fromString("public"))
    }
}

