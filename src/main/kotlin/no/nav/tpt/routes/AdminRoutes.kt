package no.nav.tpt.routes

import io.ktor.http.*
import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import no.nav.tpt.plugins.TokenPrincipal
import no.nav.tpt.plugins.dependencies

fun Route.adminRoutes() {
    authenticate("auth-bearer") {
        route("/admin") {
            get("/status") {
                val principal = call.principal<TokenPrincipal>()!!
                val adminAuthService = call.dependencies.adminAuthorizationService
                
                if (!adminAuthService.isAdmin(principal.groups)) {
                    call.respondForbidden("User does not have admin privileges")
                    return@get
                }
                
                call.respond(HttpStatusCode.OK, mapOf("status" to "OK"))
            }
            
            get("/teams/overview") {
                val principal = call.principal<TokenPrincipal>()!!
                val adminAuthService = call.dependencies.adminAuthorizationService
                
                if (!adminAuthService.isAdmin(principal.groups)) {
                    call.respondForbidden("User does not have admin privileges")
                    return@get
                }
                
                try {
                    val adminService = call.dependencies.adminService
                    val overview = adminService.getTeamsOverview()
                    call.respond(HttpStatusCode.OK, overview)
                } catch (e: Exception) {
                    call.respondInternalServerError("Failed to fetch teams overview", e)
                }
            }
            
            get("/teams/sla") {
                val principal = call.principal<TokenPrincipal>()!!
                val adminAuthService = call.dependencies.adminAuthorizationService
                
                if (!adminAuthService.isAdmin(principal.groups)) {
                    call.respondForbidden("User does not have admin privileges")
                    return@get
                }
                
                try {
                    val adminService = call.dependencies.adminService
                    val slaReport = adminService.getTeamsSlaReport()
                    call.respond(HttpStatusCode.OK, slaReport)
                } catch (e: Exception) {
                    call.respondInternalServerError("Failed to fetch teams SLA report", e)
                }
            }
        }
    }
}
