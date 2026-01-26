package no.nav.tpt.domain.user

import kotlinx.serialization.Serializable

@Serializable
enum class UserRole {
    DEVELOPER,
    TEAM_MEMBER,
    LEADER,
    NONE
}
