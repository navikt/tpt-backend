package no.nav.tpt.infrastructure.nais

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

interface GraphQLErrorInterface {
    val message: String
    val path: List<String>?
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
        val appAfter: String? = null,
        val teamsFirst: Int = 10,
        val teamsAfter: String? = null
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
        val pageInfo: PageInfo,
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
        val ingresses: List<Ingress>,
        val deployments: Deployments
    )

    @Serializable
    data class Ingress(
        val type: String
    )

    @Serializable
    data class Deployments(
        val nodes: List<Deployment>
    )

    @Serializable
    data class Deployment(
        val environmentName: String
    )

    @Serializable
    data class GraphQLError(
        override val message: String,
        override val path: List<String>? = null
    ) : GraphQLErrorInterface
}

@Serializable
data class WorkloadVulnerabilitiesRequest(
    val query: String,
    val variables: Variables
) {
    @Serializable
    data class Variables(
        val email: String,
        val teamFirst: Int = 1,
        val teamAfter: String? = null,
        val workloadFirst: Int = 50,
        val workloadAfter: String? = null,
        val vulnFirst: Int = 50,
        val vulnAfter: String? = null
    )
}

@Serializable
data class WorkloadVulnerabilitiesResponse(
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
        val pageInfo: PageInfo,
        val nodes: List<TeamNode>
    )

    @Serializable
    data class TeamNode(
        val team: Team
    )

    @Serializable
    data class Team(
        val slug: String,
        val applications: WorkloadConnection? = null,
        val jobs: WorkloadConnection? = null
    )

    @Serializable
    data class WorkloadConnection(
        val pageInfo: PageInfo,
        val nodes: List<WorkloadNode>
    )

    @Serializable
    data class PageInfo(
        val hasNextPage: Boolean,
        val endCursor: String?
    )

    @Serializable
    data class WorkloadNode(
        val id: String,
        val name: String,
        val ingresses: List<Ingress> = emptyList(),
        val deployments: Deployments,
        val image: Image?
    )

    @Serializable
    data class Ingress(
        val type: String
    )

    @Serializable
    data class Deployments(
        val nodes: List<Deployment>
    )

    @Serializable
    data class Deployment(
        val repository: String?,
        val environmentName: String?
    )

    @Serializable
    data class Image(
        val name: String,
        val tag: String,
        val vulnerabilities: Vulnerabilities
    )

    @Serializable
    data class Vulnerabilities(
        val pageInfo: PageInfo,
        val nodes: List<Vulnerability>
    )

    @Serializable
    data class Vulnerability(
        val identifier: String,
        val severity: String,
        @SerialName("package")
        val packageName: String?,
        val description: String?,
        val vulnerabilityDetailsLink: String?,
        val suppression: Suppression?
    )

    @Serializable
    data class Suppression(
        val state: String
    )

    @Serializable
    data class GraphQLError(
        override val message: String,
        override val path: List<String>? = null
    ) : GraphQLErrorInterface
}

@Serializable
data class TeamWorkloadVulnerabilitiesRequest(
    val query: String,
    val variables: Variables
) {
    @Serializable
    data class Variables(
        val team: String,
        val workloadFirst: Int = 50,
        val workloadAfter: String? = null,
        val vulnFirst: Int = 50,
        val vulnAfter: String? = null
    )
}

@Serializable
data class TeamWorkloadVulnerabilitiesResponse(
    val data: Data? = null,
    val errors: List<GraphQLError>? = null
) {
    @Serializable
    data class Data(
        val team: Team?
    )

    @Serializable
    data class Team(
        val slug: String,
        val applications: WorkloadConnection? = null,
        val jobs: WorkloadConnection? = null
    )

    @Serializable
    data class WorkloadConnection(
        val pageInfo: PageInfo,
        val nodes: List<WorkloadNode>
    )

    @Serializable
    data class PageInfo(
        val hasNextPage: Boolean,
        val endCursor: String?
    )

    @Serializable
    data class WorkloadNode(
        val id: String,
        val name: String,
        val ingresses: List<Ingress> = emptyList(),
        val deployments: Deployments,
        val image: Image?
    )

    @Serializable
    data class Ingress(
        val type: String
    )

    @Serializable
    data class Deployments(
        val nodes: List<Deployment>
    )

    @Serializable
    data class Deployment(
        val repository: String?,
        val environmentName: String?
    )

    @Serializable
    data class Image(
        val name: String,
        val tag: String,
        val vulnerabilities: Vulnerabilities
    )

    @Serializable
    data class Vulnerabilities(
        val pageInfo: PageInfo,
        val nodes: List<Vulnerability>
    )

    @Serializable
    data class Vulnerability(
        val identifier: String,
        val severity: String,
        @SerialName("package")
        val packageName: String?,
        val description: String?,
        val vulnerabilityDetailsLink: String?,
        val suppression: Suppression?
    )

    @Serializable
    data class Suppression(
        val state: String
    )

    @Serializable
    data class GraphQLError(
        override val message: String,
        override val path: List<String>? = null
    ) : GraphQLErrorInterface
}

@Serializable
data class TeamMembershipsForUserRequest(
    val query: String,
    val variables: Variables
) {
    @Serializable
    data class Variables(
        val email: String
    )
}

@Serializable
data class TeamMembershipsForUserResponse(
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
        val slug: String
    )

    @Serializable
    data class GraphQLError(
        override val message: String,
        override val path: List<String>? = null
    ) : GraphQLErrorInterface
}
