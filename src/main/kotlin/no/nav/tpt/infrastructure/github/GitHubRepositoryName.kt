package no.nav.tpt.infrastructure.github

internal fun normalizeGitHubRepositoryName(name: String): String =
    if ('/' in name) name else "navikt/$name"
