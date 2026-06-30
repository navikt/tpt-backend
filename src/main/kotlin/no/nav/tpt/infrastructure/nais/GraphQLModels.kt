package no.nav.tpt.infrastructure.nais

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

const val APP_VULNERABILITIES_FOR_USER_QUERY = $$"""
query ApplicationVulnerabilitiesForUser($email: String!, $teamFirst: Int = 1, $teamAfter: Cursor, $workloadFirst: Int = 50, $workloadAfter: Cursor, $vulnFirst: Int = 50, $vulnAfter: Cursor) {
  user(email: $email) {
    teams(first: $teamFirst, after: $teamAfter) {
      pageInfo {
        hasNextPage
        endCursor
      }
      nodes {
        team {
          slug
          applications(first: $workloadFirst, after: $workloadAfter) {
            pageInfo {
              hasNextPage
              endCursor
            }
            nodes {
              id
              name
              ingresses {
                type
              }
              deployments(first: 1) {
                nodes {
                  repository
                  environmentName
                  createdAt
                }
              }
              image {
                name
                tag
                vulnerabilities(first: $vulnFirst, after: $vulnAfter) {
                  pageInfo {
                    hasNextPage
                    endCursor
                  }
                  nodes {
                    identifier
                    description
                    vulnerabilityDetailsLink
                    severity
                    package
                    suppression {
                      state
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
"""

const val JOB_VULNERABILITIES_FOR_USER_QUERY = $$"""
query JobVulnerabilitiesForUser($email: String!, $teamFirst: Int = 1, $teamAfter: Cursor, $workloadFirst: Int = 50, $workloadAfter: Cursor, $vulnFirst: Int = 50, $vulnAfter: Cursor) {
  user(email: $email) {
    teams(first: $teamFirst, after: $teamAfter) {
      pageInfo {
        hasNextPage
        endCursor
      }
      nodes {
        team {
          slug
          jobs(first: $workloadFirst, after: $workloadAfter) {
            pageInfo {
              hasNextPage
              endCursor
            }
            nodes {
              id
              name
              deployments(first: 1) {
                nodes {
                  repository
                  environmentName
                  createdAt
                }
              }
              image {
                name
                tag
                vulnerabilities(first: $vulnFirst, after: $vulnAfter) {
                  pageInfo {
                    hasNextPage
                    endCursor
                  }
                  nodes {
                    identifier
                    description
                    vulnerabilityDetailsLink
                    severity
                    package
                    suppression {
                      state
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
"""

const val APP_VULNERABILITIES_FOR_TEAM_QUERY = $$"""
query ApplicationVulnerabilitiesForTeam($team: Slug!, $workloadFirst: Int = 50, $workloadAfter: Cursor, $vulnFirst: Int = 50, $vulnAfter: Cursor) {
  team(slug: $team) {
    slug
    applications(first: $workloadFirst, after: $workloadAfter) {
      pageInfo {
        hasNextPage
        endCursor
      }
      nodes {
        id
        name
        ingresses {
          type
        }
        deployments(first: 1) {
          nodes {
            repository
            environmentName
            createdAt
          }
        }
        image {
          name
          tag
          vulnerabilities(first: $vulnFirst, after: $vulnAfter) {
            pageInfo {
              hasNextPage
              endCursor
            }
            nodes {
              identifier
              description
              vulnerabilityDetailsLink
              severity
              package
              suppression {
                state
              }
            }
          }
        }
      }
    }
  }
}
"""

const val JOB_VULNERABILITIES_FOR_TEAM_QUERY = $$"""
query JobVulnerabilitiesForTeam($team: Slug!, $workloadFirst: Int = 50, $workloadAfter: Cursor, $vulnFirst: Int = 50, $vulnAfter: Cursor) {
  team(slug: $team) {
    slug
    jobs(first: $workloadFirst, after: $workloadAfter) {
      pageInfo {
        hasNextPage
        endCursor
      }
      nodes {
        id
        name
        deployments(first: 1) {
          nodes {
            repository
            environmentName
            createdAt
          }
        }
        image {
          name
          tag
          vulnerabilities(first: $vulnFirst, after: $vulnAfter) {
            pageInfo {
              hasNextPage
              endCursor
            }
            nodes {
              identifier
              description
              vulnerabilityDetailsLink
              severity
              package
              suppression {
                state
              }
            }
          }
        }
      }
    }
  }
}
"""

const val TEAM_MEMBERSHIPS_FOR_USER_QUERY = $$"""
query TeamMembershipsForUser($email: String!) {
  user(email: $email) {
    teams {
      nodes {
        team {
          slug
        }
      }
    }
  }
}
"""

const val TEAM_INFORMATION_QUERY = $$"""
query TeamInformation($teamFirst: Int = 200, $teamAfter: Cursor) {
  teams(
    first: $teamFirst,
    after: $teamAfter,
    filter: {hasWorkloads: true}
  ) {
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
      slug
      slackChannel
    }
  }
}
"""

interface GraphQLErrorInterface {
    val message: String
    val path: List<String>?
}

// Shared GraphQL response types used by multiple queries
object GraphQLTypes {
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
        val environmentName: String?,
        val createdAt: String?
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
    data class WorkloadConnection(
        val pageInfo: PageInfo,
        val nodes: List<WorkloadNode>
    )

    @Serializable
    data class Team(
        val slug: String,
        val applications: WorkloadConnection? = null,
        val jobs: WorkloadConnection? = null
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
    val errors: List<GraphQLTypes.GraphQLError>? = null
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
        val pageInfo: GraphQLTypes.PageInfo,
        val nodes: List<TeamNode>
    )

    @Serializable
    data class TeamNode(
        val team: GraphQLTypes.Team
    )
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
    val errors: List<GraphQLTypes.GraphQLError>? = null
) {
    @Serializable
    data class Data(
        val team: GraphQLTypes.Team?
    )
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

@Serializable
data class TeamInformationRequest(
    val query: String,
    val variables: Variables = Variables()
) {
    @Serializable
    data class Variables(
        val teamFirst: Int = 200,
        val teamAfter: String? = null
    )
}

@Serializable
data class TeamInformationResponse(
    val data: Data? = null,
    val errors: List<GraphQLError>? = null
) {
    @Serializable
    data class Data(
        val teams: Teams
    )

    @Serializable
    data class Teams(
        val pageInfo: PageInfo,
        val nodes: List<TeamNode>
    )

    @Serializable
    data class PageInfo(
        val hasNextPage: Boolean,
        val endCursor: String?
    )

    @Serializable
    data class TeamNode(
        val slug: String,
        val slackChannel: String?
    )

    @Serializable
    data class GraphQLError(
        override val message: String,
        override val path: List<String>? = null
    ) : GraphQLErrorInterface
}
