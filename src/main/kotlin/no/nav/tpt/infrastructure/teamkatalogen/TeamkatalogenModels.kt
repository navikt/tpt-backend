package no.nav.tpt.infrastructure.teamkatalogen

import kotlinx.serialization.Serializable

@Serializable
data class MembershipResponse(
    val teams: List<TeamMembership>
)

@Serializable
data class TeamMembership(
    val naisTeams: List<String>
)

