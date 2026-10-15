package no.nav.tpt.infrastructure.securitystatus

import org.jetbrains.exposed.v1.core.Table
import org.jetbrains.exposed.v1.javatime.timestamp

object Workloads : Table("workloads") {
    val appNaisId = varchar("app_nais_id", 255)
    val teamSlug = varchar("team_slug", 100)
    val appName = varchar("app_name", 255)
    val workloadType = varchar("workload_type", 20)
    val environment = varchar("environment", 100).nullable()
    val firstSeenAt = timestamp("first_seen_at")
    val removedAt = timestamp("removed_at").nullable()

    override val primaryKey = PrimaryKey(appNaisId)
}

object WorkloadDeployments : Table("workload_deployments") {
    val appNaisId = varchar("app_nais_id", 255).references(Workloads.appNaisId)
    val deployedAt = timestamp("deployed_at")

    override val primaryKey = PrimaryKey(appNaisId, deployedAt)
}

object WorkloadAbsences : Table("workload_absences") {
    val appNaisId = varchar("app_nais_id", 255).references(Workloads.appNaisId)
    val removedAt = timestamp("removed_at")
    val returnedAt = timestamp("returned_at")

    override val primaryKey = PrimaryKey(appNaisId, removedAt)
}
