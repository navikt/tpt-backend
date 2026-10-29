package no.nav.tpt.domain.securitystatus

import no.nav.tpt.domain.vulnerability.SlaPolicy
import no.nav.tpt.domain.vulnerability.ResolutionGap
import no.nav.tpt.domain.vulnerability.VulnerabilityLifecycle
import java.time.Duration
import java.time.Instant
import java.time.ZonedDateTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SecurityStatusEvaluatorTest {
    private val evaluator = SecurityStatusEvaluator(SlaPolicy(), SecurityStatusConfig())
    private val now: Instant = ZonedDateTime.of(2026, 10, 14, 12, 0, 0, 0, SlaPolicy.OSLO).toInstant()

    private fun daysAgo(days: Long): Instant = now.minus(Duration.ofDays(days))

    private fun workload(
        id: String = "app-1",
        name: String = "app",
        firstSeenDaysAgo: Long = 100,
        deployedDaysAgo: Long? = 1,
        removedDaysAgo: Long? = null,
    ) = WorkloadFact(
        teamSlug = "team",
        appNaisId = id,
        appName = name,
        firstSeenAt = daysAgo(firstSeenDaysAgo),
        removedAt = removedDaysAgo?.let { daysAgo(it) },
        deployments = listOfNotNull(deployedDaysAgo?.let { daysAgo(it) }),
    )

    private fun vuln(
        appId: String = "app-1",
        appName: String = "app",
        severity: String = "CRITICAL",
        discoveredDaysAgo: Long,
        resolvedDaysAgo: Long? = null,
    ) = VulnerabilityLifecycle(
        teamSlug = "team",
        appNaisId = appId,
        appName = appName,
        severity = severity,
        discoveredAt = daysAgo(discoveredDaysAgo),
        resolvedAt = resolvedDaysAgo?.let { daysAgo(it) },
    )

    @Test
    fun `should return null when team has no workloads`() {
        assertNull(evaluator.evaluate("team", emptyList(), emptyList(), now))
    }

    @Test
    fun `should be green with no level for healthy team`() {
        val status = evaluator.evaluate("team", emptyList(), listOf(workload()), now)!!

        assertEquals(SecurityStatusColor.GREEN, status.exposed.status)
        assertEquals(SecurityStatusColor.GREEN, status.trend.status)
        assertEquals(SecurityStatusColor.GREEN, status.maintenance.status)
        assertNull(status.level)
        assertNull(status.exposed.since)
    }

    @Test
    fun `should be yellow when one app has an overdue critical vulnerability`() {
        val status = evaluator.evaluate("team", listOf(vuln(discoveredDaysAgo = 3)), listOf(workload()), now)!!

        assertEquals(SecurityStatusColor.YELLOW, status.exposed.status)
        assertEquals(1, status.exposed.appsPastDeadline.size)
        assertNotNull(status.exposed.since)
    }

    @Test
    fun `should be red when one app is overdue by five workdays or more`() {
        val status = evaluator.evaluate("team", listOf(vuln(discoveredDaysAgo = 20)), listOf(workload()), now)!!

        assertEquals(SecurityStatusColor.RED, status.exposed.status)
    }

    @Test
    fun `should be red when two apps are overdue`() {
        val workloads = listOf(workload("a", "a"), workload("b", "b"))
        val vulns = listOf(
            vuln("a", "a", discoveredDaysAgo = 3),
            vuln("b", "b", discoveredDaysAgo = 3),
        )

        val status = evaluator.evaluate("team", vulns, workloads, now)!!

        assertEquals(SecurityStatusColor.RED, status.exposed.status)
    }

    @Test
    fun `should not count resolved vulnerabilities as exposed`() {
        val vulns = listOf(vuln(discoveredDaysAgo = 20, resolvedDaysAgo = 10))

        val status = evaluator.evaluate("team", vulns, listOf(workload()), now)!!

        assertEquals(SecurityStatusColor.GREEN, status.exposed.status)
        assertTrue(status.history.any { it.needsAttentionDays + it.actNowDays > 0 })
    }

    @Test
    fun `should use three month deadline for non critical vulnerabilities`() {
        val within = evaluator.evaluate("team", listOf(vuln(severity = "HIGH", discoveredDaysAgo = 60)), listOf(workload()), now)!!
        val past = evaluator.evaluate("team", listOf(vuln(severity = "HIGH", discoveredDaysAgo = 95)), listOf(workload()), now)!!

        assertEquals(SecurityStatusColor.GREEN, within.exposed.status)
        assertEquals(SecurityStatusColor.YELLOW, past.exposed.status)
    }

    @Test
    fun `should flag apps not deployed within the configured limit`() {
        val workloads = listOf(
            workload("a", "a", deployedDaysAgo = 10),
            workload("c", "c", deployedDaysAgo = 20),
            workload("d", "d", deployedDaysAgo = 30),
            workload("b", "b", deployedDaysAgo = 71),
        )

        val status = evaluator.evaluate("team", emptyList(), workloads, now)!!

        assertEquals(SecurityStatusColor.YELLOW, status.maintenance.status)
        assertEquals(3, status.maintenance.upToDate)
        assertEquals(4, status.maintenance.total)
        assertEquals(listOf(AppOverdueRebuild("b", 11)), status.maintenance.overdueRebuild)
    }

    @Test
    fun `should be red for maintenance below yellow ratio`() {
        val workloads = listOf(workload("a", "a", deployedDaysAgo = 200), workload("b", "b", deployedDaysAgo = 1))

        val status = evaluator.evaluate("team", emptyList(), workloads, now)!!

        assertEquals(SecurityStatusColor.RED, status.maintenance.status)
    }

    @Test
    fun `should include workloads without vulnerabilities in application count`() {
        val status = evaluator.evaluate("team", emptyList(), listOf(workload("a"), workload("b"), workload("c", removedDaysAgo = 5)), now)!!

        assertEquals(2, status.applicationCount)
    }

    @Test
    fun `should limit history to recorded data`() {
        val status = evaluator.evaluate("team", emptyList(), listOf(workload(firstSeenDaysAgo = 40)), now)!!

        assertEquals(2, status.history.size)
        assertEquals(status.history.size, status.trend.appsWithOverduePerMonth.size)
    }

    @Test
    fun `should cap history at configured months`() {
        val status = evaluator.evaluate("team", emptyList(), listOf(workload(firstSeenDaysAgo = 900)), now)!!

        assertEquals(6, status.history.size)
    }

    @Test
    fun `should suppress trend until a full window of data exists`() {
        val vulns = (1..5).map { vuln(severity = "LOW", discoveredDaysAgo = 2) }

        val status = evaluator.evaluate("team", vulns, listOf(workload(firstSeenDaysAgo = 10)), now)!!

        assertEquals(TrendDirection.STABLE, status.trend.direction)
        assertEquals(SecurityStatusColor.GREEN, status.trend.status)
    }

    @Test
    fun `should report worse trend when more vulnerabilities are discovered than resolved`() {
        val vulns = (1..5).map { vuln(severity = "LOW", discoveredDaysAgo = 5) }

        val status = evaluator.evaluate("team", vulns, listOf(workload(firstSeenDaysAgo = 100)), now)!!

        assertEquals(TrendDirection.WORSE, status.trend.direction)
        assertEquals(SecurityStatusColor.YELLOW, status.trend.status)
    }

    @Test
    fun `should report improving trend when more are resolved than discovered`() {
        val vulns = (1..5).map { vuln(severity = "LOW", discoveredDaysAgo = 60, resolvedDaysAgo = 5) }

        val status = evaluator.evaluate("team", vulns, listOf(workload(firstSeenDaysAgo = 100)), now)!!

        assertEquals(TrendDirection.IMPROVING, status.trend.direction)
    }

    @Test
    fun `should apply changed thresholds to the whole evaluation`() {
        val strict = SecurityStatusEvaluator(SlaPolicy(), SecurityStatusConfig(deployMaxAgeDays = 5))

        val status = strict.evaluate("team", emptyList(), listOf(workload(deployedDaysAgo = 10)), now)!!

        assertEquals(SecurityStatusColor.RED, status.maintenance.status)
    }

    @Test
    fun `should set level new for recently off track team`() {
        val status = evaluator.evaluate("team", listOf(vuln(discoveredDaysAgo = 2)), listOf(workload()), now)!!

        assertEquals(SecurityLevel.NEW, status.level)
    }

    @Test
    fun `should set level chronic when off track for three months`() {
        val vulns = listOf(vuln(severity = "HIGH", discoveredDaysAgo = 190))

        val status = evaluator.evaluate("team", vulns, listOf(workload(firstSeenDaysAgo = 200)), now)!!

        assertEquals(SecurityLevel.CHRONIC, status.level)
    }

    @Test
    fun `should count exposure for a vulnerability that went overdue and was resolved the same day`() {
        val discovered = now.minus(Duration.ofDays(5))
        val deadline = SlaPolicy().evaluate("CRITICAL", discovered, discovered).deadline
        val resolved = deadline.plus(Duration.ofHours(2))
        val vuln = VulnerabilityLifecycle("team", "app-1", "app", "CRITICAL", discovered, resolved)

        val status = evaluator.evaluate("team", listOf(vuln), listOf(workload()), now)!!

        assertTrue(status.history.any { it.needsAttentionDays + it.actNowDays > 0 })
    }

    @Test
    fun `should list same-named apps in different environments separately`() {
        val vulns = listOf(
            vuln(appId = "a-dev", appName = "app", discoveredDaysAgo = 20),
            vuln(appId = "a-prod", appName = "app", discoveredDaysAgo = 20),
        )
        val workloads = listOf(workload(id = "a-dev"), workload(id = "a-prod"))

        val status = evaluator.evaluate("team", vulns, workloads, now)!!

        assertEquals(2, status.exposed.appsPastDeadline.size)
    }

    @Test
    fun `should count workload without deployment using first seen time`() {
        val status = evaluator.evaluate("team", emptyList(), listOf(workload(firstSeenDaysAgo = 100, deployedDaysAgo = null)), now)!!

        assertEquals(1, status.maintenance.total)
        assertEquals(0, status.maintenance.upToDate)
        assertEquals(SecurityStatusColor.RED, status.maintenance.status)
    }

    @Test
    fun `should not count time between resolution and reappearance as overdue`() {
        val discovered = daysAgo(60)
        val gap = ResolutionGap(daysAgo(50), daysAgo(1))
        val vuln = VulnerabilityLifecycle("team", "app-1", "app", "LOW", discovered, null, listOf(gap))
        val flat = VulnerabilityLifecycle("team", "app-1", "app", "LOW", discovered, null)

        val withGap = evaluator.evaluate("team", listOf(vuln), listOf(workload()), now)!!
        val without = evaluator.evaluate("team", listOf(flat), listOf(workload()), now)!!

        val gapDays = withGap.history.sumOf { it.needsAttentionDays + it.actNowDays }
        val flatDays = without.history.sumOf { it.needsAttentionDays + it.actNowDays }
        assertTrue(gapDays <= flatDays)
        assertEquals(0, withGap.history.first().needsAttentionDays + withGap.history.first().actNowDays)
    }

    @Test
    fun `should not count workload as present during absence`() {
        val absent = workload(firstSeenDaysAgo = 100).copy(absences = listOf(WorkloadAbsence(daysAgo(30), daysAgo(1))))
        val status = evaluator.evaluate("team", emptyList(), listOf(absent), now)!!

        assertEquals(1, status.maintenance.total)
    }

    @Test
    fun `should report recovery as on track days rather than a red month`() {
        val baseline = Instant.parse("2026-10-01T00:00:00Z")
        val at = Instant.parse("2026-10-28T12:00:00Z")
        val app = workload().copy(firstSeenAt = baseline, deployments = listOf(baseline))
        val finding = VulnerabilityLifecycle(
            "team", "app-1", "app", "CRITICAL",
            Instant.parse("2026-09-01T10:00:00Z"),
            Instant.parse("2026-10-02T10:00:00Z"),
        )

        val status = evaluator.evaluate("team", listOf(finding), listOf(app), at)!!

        assertEquals(SecurityStatusColor.GREEN, status.exposed.status)
        assertEquals(SecurityStatusColor.GREEN, status.trend.status)
        assertEquals(SecurityStatusColor.GREEN, status.maintenance.status)
        assertEquals(
            listOf(MonthlySecurityHistory("2026-10", "2026-10-28", 26, 0, 2, 0, true)),
            status.history,
        )
    }

    @Test
    fun `should exclude days before tracking and only fully absent days from the denominator`() {
        val baseline = Instant.parse("2026-10-10T00:00:00Z")
        val at = Instant.parse("2026-10-28T12:00:00Z")
        val app = workload().copy(
            firstSeenAt = baseline,
            deployments = listOf(baseline),
            absences = listOf(
                WorkloadAbsence(
                    Instant.parse("2026-10-15T00:00:00Z"),
                    Instant.parse("2026-10-18T00:00:00Z"),
                ),
            ),
        )

        val status = evaluator.evaluate("team", emptyList(), listOf(app), at)!!

        assertEquals(
            listOf(MonthlySecurityHistory("2026-10", "2026-10-28", 17, 0, 0, 11, true)),
            status.history,
        )
    }

    @Test
    fun `should retain overdue exposure on the day the last workload is removed`() {
        val started = now.atZone(SlaPolicy.OSLO).toLocalDate().minusDays(1)
            .atStartOfDay(SlaPolicy.OSLO).toInstant()
        val removed = now.minus(Duration.ofHours(2))
        val app = workload().copy(
            firstSeenAt = started,
            removedAt = removed,
            deployments = listOf(started),
        )
        val finding = vuln(discoveredDaysAgo = 20).copy(resolvedAt = removed)

        val status = evaluator.evaluate("team", listOf(finding), listOf(app), now)!!

        assertEquals(
            listOf(MonthlySecurityHistory("2026-10", "2026-10-14", 0, 0, 2, 12, true)),
            status.history,
        )
        assertEquals(0, status.maintenance.total)
    }

    @Test
    fun `should retain overdue exposure before an intraday absence starts`() {
        val started = now.atZone(SlaPolicy.OSLO).toLocalDate().minusDays(1)
            .atStartOfDay(SlaPolicy.OSLO).toInstant()
        val absentFrom = now.minus(Duration.ofHours(2))
        val app = workload().copy(
            firstSeenAt = started,
            deployments = listOf(started),
            absences = listOf(WorkloadAbsence(absentFrom, now.plus(Duration.ofDays(1)))),
        )
        val finding = vuln(discoveredDaysAgo = 20).copy(resolvedAt = absentFrom)

        val status = evaluator.evaluate("team", listOf(finding), listOf(app), now)!!

        assertEquals(
            listOf(MonthlySecurityHistory("2026-10", "2026-10-14", 0, 0, 2, 12, true)),
            status.history,
        )
        assertEquals(0, status.maintenance.total)
    }

    @Test
    fun `should count removal at Oslo midnight only on the preceding day`() {
        val today = now.atZone(SlaPolicy.OSLO).toLocalDate()
        val started = today.minusDays(2).atStartOfDay(SlaPolicy.OSLO).toInstant()
        val removed = today.minusDays(1).atStartOfDay(SlaPolicy.OSLO).toInstant()
        val app = workload().copy(
            firstSeenAt = started,
            removedAt = removed,
            deployments = listOf(started),
        )
        val finding = vuln(discoveredDaysAgo = 20).copy(resolvedAt = removed)

        val status = evaluator.evaluate("team", listOf(finding), listOf(app), now)!!

        assertEquals(
            listOf(MonthlySecurityHistory("2026-10", "2026-10-14", 0, 0, 1, 13, true)),
            status.history,
        )
    }

    @Test
    fun `should count a workload created and removed between daily evaluation times`() {
        val started = now.minus(Duration.ofHours(28))
        val removed = now.minus(Duration.ofHours(26))
        val app = workload().copy(
            firstSeenAt = started,
            removedAt = removed,
            deployments = listOf(started),
        )
        val finding = vuln(discoveredDaysAgo = 20).copy(resolvedAt = removed)

        val status = evaluator.evaluate("team", listOf(finding), listOf(app), now)!!

        assertEquals(
            listOf(MonthlySecurityHistory("2026-10", "2026-10-14", 0, 0, 1, 13, true)),
            status.history,
        )
    }

    @Test
    fun `should date complete months across a year boundary and retain yellow days`() {
        val baseline = Instant.parse("2025-12-01T00:00:00Z")
        val at = Instant.parse("2026-01-03T12:00:00Z")
        val app = workload().copy(firstSeenAt = baseline, deployments = listOf(baseline))
        val finding = VulnerabilityLifecycle(
            "team", "app-1", "app", "CRITICAL",
            Instant.parse("2025-12-28T10:00:00Z"),
            Instant.parse("2025-12-30T10:00:00Z"),
        )

        val status = evaluator.evaluate("team", listOf(finding), listOf(app), at)!!

        assertEquals(
            listOf(
                MonthlySecurityHistory("2025-12", "2025-12-31", 29, 2, 0, 0, false),
                MonthlySecurityHistory("2026-01", "2026-01-03", 3, 0, 0, 0, true),
            ),
            status.history,
        )
    }
}
