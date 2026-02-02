package no.nav.tpt.infrastructure.user

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AdminAuthorizationServiceTest {

    @Test
    fun `should return true when user has admin group`() {
        val service = AdminAuthorizationServiceImpl("admin-group-1,admin-group-2")
        
        assertTrue(service.isAdmin(listOf("admin-group-1", "other-group")))
    }

    @Test
    fun `should return false when user has no admin group`() {
        val service = AdminAuthorizationServiceImpl("admin-group-1,admin-group-2")
        
        assertFalse(service.isAdmin(listOf("other-group", "another-group")))
    }

    @Test
    fun `should return false when admin groups not configured`() {
        val service = AdminAuthorizationServiceImpl(null)
        
        assertFalse(service.isAdmin(listOf("any-group")))
    }

    @Test
    fun `should handle empty user groups list`() {
        val service = AdminAuthorizationServiceImpl("admin-group-1")
        
        assertFalse(service.isAdmin(emptyList()))
    }

    @Test
    fun `should trim whitespace from admin groups config`() {
        val service = AdminAuthorizationServiceImpl(" admin-group-1 , admin-group-2 ")
        
        assertTrue(service.isAdmin(listOf("admin-group-1")))
        assertTrue(service.isAdmin(listOf("admin-group-2")))
    }
}
