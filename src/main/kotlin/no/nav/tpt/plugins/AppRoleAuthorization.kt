package no.nav.tpt.plugins

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.routing.*

/** Custom Entra ID app roles, granted per consumer via `accessPolicy.inbound.rules[].permissions.roles`. */
object AppRole {
    const val DATA_COLLECTOR_CALLBACKS = "data-collector-callbacks"
    const val TEAM_VULNERABILITIES_READ = "team-vulnerabilities-read"
}

private class RequireAppRoleConfig {
    var role: String = ""
}

private val RequireAppRole = createRouteScopedPlugin("RequireAppRole", ::RequireAppRoleConfig) {
    val role = pluginConfig.role
    on(AuthenticationChecked) { call ->
        val principal = call.principal<ApplicationPrincipal>() ?: return@on
        if (role !in principal.roles) {
            application.log.warn("Rejected application ${principal.clientName} (${principal.clientId}): missing role $role")
            throw ForbiddenException("Application is missing required role")
        }
    }
}

private class AppRoleRouteSelector(private val role: String) : RouteSelector() {
    override suspend fun evaluate(context: RoutingResolveContext, segmentIndex: Int) =
        RouteSelectorEvaluation.Transparent

    override fun toString() = "(app role $role)"
}

fun Route.withAppRole(role: String, build: Route.() -> Unit): Route {
    val child = createChild(AppRoleRouteSelector(role))
    child.install(RequireAppRole) { this.role = role }
    child.build()
    return child
}
