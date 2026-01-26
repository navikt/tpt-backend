package no.nav.tpt.infrastructure.teamkatalogen

import kotlinx.serialization.Serializable

@Serializable
data class MembershipResponse(
    val naisTeams: List<String>,
    val clusters: List<TeamkatalogenEntity> = emptyList(),
    val productAreas: List<TeamkatalogenEntity> = emptyList()
)

@Serializable
data class TeamkatalogenEntity(
    val id: String,
    val name: String? = null
)

@Serializable
data class SubteamsResponse(
    val content: List<SubteamData>
)

@Serializable
data class SubteamData(
    val id: String,
    val name: String? = null,
    val naisTeams: List<String>
)

@Serializable
internal data class TeamkatalogenApiResponse(
    val teams: List<TeamMembership>,
    val clusters: List<ClusterMembership> = emptyList(),
    val productAreas: List<ProductAreaMembership> = emptyList()
)

@Serializable
internal data class TeamMembership(
    val naisTeams: List<String>
)

@Serializable
internal data class ClusterMembership(
    val id: String,
    val name: String? = null
)

@Serializable
internal data class ProductAreaMembership(
    val id: String,
    val name: String? = null
)

