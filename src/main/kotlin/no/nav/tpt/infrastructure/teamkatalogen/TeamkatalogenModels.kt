package no.nav.tpt.infrastructure.teamkatalogen

import kotlinx.serialization.Serializable

@Serializable
data class MembershipResponse(
    val naisTeams: List<String>
)

@Serializable
internal data class TeamkatalogenApiResponse(
    val teams: List<TeamMembership>
)

@Serializable
internal data class TeamMembership(
    val naisTeams: List<String>
)

