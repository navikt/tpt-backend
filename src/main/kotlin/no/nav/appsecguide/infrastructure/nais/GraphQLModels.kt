package no.nav.appsecguide.infrastructure.nais

import kotlinx.serialization.Serializable

interface GraphQLErrorInterface {
    val message: String
    val path: List<String>?
}

@Serializable
data class ApplicationsForTeamRequest(
    val query: String,
    val variables: Variables
) {
    @Serializable
    data class Variables(
        val teamSlug: String,
        val appFirst: Int = 100,
        val appAfter: String? = null
    )
}

@Serializable
data class ApplicationsForTeamResponse(
    val data: Data? = null,
    val errors: List<GraphQLError>? = null
) {
    @Serializable
    data class Data(
        val team: Team?
    )

    @Serializable
    data class Team(
        val applications: Applications
    )

    @Serializable
    data class Applications(
        val pageInfo: PageInfo,
        val nodes: List<Application>
    )

    @Serializable
    data class PageInfo(
        val hasNextPage: Boolean,
        val endCursor: String?
    )


    @Serializable
    data class Application(
        val name: String,
        val ingresses: List<Ingress>
    )

    @Serializable
    data class Ingress(
        val type: String
    )

    @Serializable
    data class GraphQLError(
        override val message: String,
        override val path: List<String>? = null
    ) : GraphQLErrorInterface
}

@Serializable
data class ApplicationsForUserRequest(
    val query: String,
    val variables: Variables
) {
    @Serializable
    data class Variables(
        val email: String,
        val appFirst: Int = 100,
        val appAfter: String? = null
    )
}

@Serializable
data class ApplicationsForUserResponse(
    val data: Data? = null,
    val errors: List<GraphQLError>? = null
) {
    @Serializable
    data class Data(
        val user: User?
    )

    @Serializable
    data class User(
        val teams: Teams
    )

    @Serializable
    data class Teams(
        val nodes: List<TeamNode>
    )

    @Serializable
    data class TeamNode(
        val team: Team
    )

    @Serializable
    data class Team(
        val slug: String,
        val applications: Applications
    )

    @Serializable
    data class Applications(
        val pageInfo: PageInfo,
        val nodes: List<Application>
    )

    @Serializable
    data class PageInfo(
        val hasNextPage: Boolean,
        val endCursor: String?
    )


    @Serializable
    data class Application(
        val name: String,
        val ingresses: List<Ingress>
    )

    @Serializable
    data class Ingress(
        val type: String
    )

    @Serializable
    data class GraphQLError(
        override val message: String,
        override val path: List<String>? = null
    ) : GraphQLErrorInterface
}

