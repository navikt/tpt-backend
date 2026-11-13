package no.nav.tpt.infrastructure.github.copilot

import kotlin.test.Test
import kotlin.test.assertEquals

class RemediationIdentityTest {

    @Test
    fun `should normalize repository URLs to owner and name`() {
        assertEquals("navikt/app", RemediationIdentity.normalizeRepository("https://github.com/navikt/app"))
        assertEquals("navikt/app", RemediationIdentity.normalizeRepository("https://github.com/navikt/app.git/"))
        assertEquals("navikt/app", RemediationIdentity.normalizeRepository("git@github.com:navikt/app.git"))
        assertEquals("navikt/app", RemediationIdentity.normalizeRepository("navikt/app"))
    }

    @Test
    fun `should give GitHub coordinates and Nais PURLs the same package identity`() {
        assertEquals(
            RemediationIdentity.packageIdentity("org.example:library"),
            RemediationIdentity.packageIdentity("pkg:maven/org.example/library@1.2.3"),
        )
        assertEquals(
            RemediationIdentity.packageIdentity("@scope/name"),
            RemediationIdentity.packageIdentity("pkg:npm/%40scope/name@4.0.0"),
        )
        assertEquals(
            RemediationIdentity.packageIdentity("github.com/foo/bar"),
            RemediationIdentity.packageIdentity("pkg:golang/github.com/foo/bar@v1.2.0"),
        )
        assertEquals(
            RemediationIdentity.packageIdentity("pkg:pypi/django@4.2.0"),
            RemediationIdentity.packageIdentity("pkg:pypi/django@5.0.0?arch=x86_64"),
        )
    }
}
