package no.nav.tpt.infrastructure.github

import kotlin.test.Test
import kotlin.test.assertEquals

class GitHubRepositoryNameTest {
    @Test
    fun `should add navikt as owner for legacy bare names`() {
        assertEquals("navikt/tpt-backend", normalizeGitHubRepositoryName("tpt-backend"))
    }

    @Test
    fun `should preserve names that already include an owner`() {
        assertEquals("navikt/tpt-backend", normalizeGitHubRepositoryName("navikt/tpt-backend"))
        assertEquals("other/tpt-backend", normalizeGitHubRepositoryName("other/tpt-backend"))
    }
}
