package no.nav.tpt.domain.securitystatus

import no.nav.tpt.domain.vulnerability.SlaPolicy
import no.nav.tpt.domain.vulnerability.VulnerabilityLifecycle
import java.time.DayOfWeek
import java.time.Duration
import java.time.Instant
import java.time.LocalDate
import java.time.YearMonth
import java.time.format.DateTimeFormatter

class SecurityStatusEvaluator(
    private val slaPolicy: SlaPolicy,
    private val config: SecurityStatusConfig,
) {
    private val zone = SlaPolicy.OSLO

    fun historyStart(now: Instant): Instant =
        now.atZone(zone).toLocalDate().minusMonths(config.historyMonths).atStartOfDay(zone).toInstant()

    fun evaluate(
        team: String,
        vulnerabilities: List<VulnerabilityLifecycle>,
        workloads: List<WorkloadFact>,
        now: Instant,
    ): TeamSecurityStatus? {
        if (workloads.isEmpty()) return null

        val today = now.atZone(zone).toLocalDate()
        val baseline = workloads.minOf { it.firstSeenAt }
        val startDate = maxOf(baseline.atZone(zone).toLocalDate(), today.minusMonths(config.historyMonths))
        val dates = generateSequence(startDate) { it.plusDays(1) }.takeWhile { !it.isAfter(today) }.toList()
        val n = dates.size
        val evalAt = dates.map { if (it == today) now else it.plusDays(1).atStartOfDay(zone).toInstant() }

        val exposure = computeExposure(vulnerabilities, evalAt)
        val exposedColors = exposure.overdueApps.indices.map { i ->
            when {
                exposure.redApps[i] > 0 || exposure.overdueApps[i] >= 2 -> SecurityStatusColor.RED
                exposure.overdueApps[i] == 1 -> SecurityStatusColor.YELLOW
                else -> SecurityStatusColor.GREEN
            }
        }

        val trendDirections = (0 until n).map { trendDirection(vulnerabilities, baseline, evalAt[it]) }
        val trendColors = (0 until n).map { i ->
            when {
                trendDirections[i] != TrendDirection.WORSE -> SecurityStatusColor.GREEN
                exposure.overdueApps[i] > 0 -> SecurityStatusColor.RED
                else -> SecurityStatusColor.YELLOW
            }
        }

        val maintenance = (0 until n).map { maintenanceAt(workloads, evalAt[it]) }
        val maintenanceColors = maintenance.map { maintenanceColor(it.first, it.second) }

        val overall = (0 until n).map { maxOf(exposedColors[it], trendColors[it], maintenanceColors[it]) }

        val last = n - 1
        val current = maintenance[last]
        val level = level(
            offTrack = overall.map { it != SecurityStatusColor.GREEN },
            reds = listOf(exposedColors[last], trendColors[last], maintenanceColors[last]).count { it == SecurityStatusColor.RED },
            dates = dates,
            today = today,
        )

        val months = dates.indices.groupBy { YearMonth.from(dates[it]) }.toSortedMap()

        return TeamSecurityStatus(
            team = team,
            applicationCount = workloads.count { it.removedAt == null },
            level = level,
            history = months.values.map { idx -> idx.maxOf { overall[it] } },
            historyAvailableFrom = iso(dates.first().atStartOfDay(zone).toInstant()),
            exposed = ExposedStatus(
                status = exposedColors[last],
                since = since(exposedColors, dates),
                appsPastDeadline = currentAppsPastDeadline(vulnerabilities, now),
            ),
            trend = TrendStatus(
                status = trendColors[last],
                since = since(trendColors, dates),
                direction = trendDirections[last],
                appsWithOverduePerMonth = months.values.map { idx -> exposure.overdueApps[idx.last()] },
            ),
            maintenance = MaintenanceStatus(
                status = maintenanceColors[last],
                since = since(maintenanceColors, dates),
                upToDate = current.first,
                total = current.second,
                overdueRebuild = overdueRebuilds(workloads, now),
            ),
        )
    }

    private class Exposure(val overdueApps: IntArray, val redApps: IntArray)

    private fun computeExposure(
        vulnerabilities: List<VulnerabilityLifecycle>,
        evalAt: List<Instant>,
    ): Exposure {
        val n = evalAt.size
        val overdueDiff = mutableMapOf<String, IntArray>()
        val redDiff = mutableMapOf<String, IntArray>()

        for (vuln in vulnerabilities) {
            val deadline = slaPolicy.evaluate(vuln.severity, vuln.discoveredAt, vuln.discoveredAt).deadline
            val start = firstIndex(0, n) { evalAt[it].isAfter(deadline) }
            val end = vuln.resolvedAt?.let { resolved -> firstIndex(0, n) { !evalAt[it].isBefore(resolved) } } ?: n
            if (start >= end) continue

            overdueDiff.getOrPut(vuln.appNaisId) { IntArray(n + 1) }.also {
                it[start]++
                it[end]--
            }
            val redStart = firstIndex(start, end) {
                slaPolicy.workdaysOverdue(deadline, evalAt[it]) >= config.exposedRedWorkdays
            }
            if (redStart < end) {
                redDiff.getOrPut(vuln.appNaisId) { IntArray(n + 1) }.also {
                    it[redStart]++
                    it[end]--
                }
            }
        }

        val overdueApps = IntArray(n)
        val redApps = IntArray(n)
        overdueDiff.values.forEach { accumulate(it, overdueApps) }
        redDiff.values.forEach { accumulate(it, redApps) }
        return Exposure(overdueApps, redApps)
    }

    private fun accumulate(diff: IntArray, target: IntArray) {
        var running = 0
        for (i in target.indices) {
            running += diff[i]
            if (running > 0) target[i]++
        }
    }

    private fun currentAppsPastDeadline(vulnerabilities: List<VulnerabilityLifecycle>, now: Instant): List<AppPastDeadline> =
        vulnerabilities
            .filter { it.resolvedAt == null }
            .mapNotNull { vuln ->
                val result = slaPolicy.evaluate(vuln.severity, vuln.discoveredAt, now)
                if (!result.isOverdue) null else vuln.appName to slaPolicy.workdaysOverdue(result.deadline, now)
            }
            .groupBy({ it.first }, { it.second })
            .map { (app, days) -> AppPastDeadline(app, days.max()) }
            .sortedWith(compareByDescending<AppPastDeadline> { it.workdaysOver }.thenBy { it.app })

    private fun trendDirection(
        vulnerabilities: List<VulnerabilityLifecycle>,
        baseline: Instant,
        at: Instant,
    ): TrendDirection {
        val windowStart = at.minus(Duration.ofDays(config.trendWindowDays))
        if (windowStart.isBefore(baseline)) return TrendDirection.STABLE

        val new = vulnerabilities.count {
            it.discoveredAt.isAfter(baseline) && it.discoveredAt.isAfter(windowStart) && !it.discoveredAt.isAfter(at)
        }
        val fixed = vulnerabilities.count {
            it.resolvedAt != null && it.resolvedAt.isAfter(windowStart) && !it.resolvedAt.isAfter(at)
        }
        val difference = kotlin.math.abs(new - fixed)
        return when {
            difference <= config.trendStableRatio * maxOf(new, fixed) -> TrendDirection.STABLE
            new > fixed -> TrendDirection.WORSE
            else -> TrendDirection.IMPROVING
        }
    }

    private fun maintenanceAt(workloads: List<WorkloadFact>, at: Instant): Pair<Int, Int> {
        var upToDate = 0
        var total = 0
        for (workload in workloads) {
            if (workload.firstSeenAt.isAfter(at)) continue
            if (workload.removedAt != null && !workload.removedAt.isAfter(at)) continue
            val latest = workload.deployments.filter { !it.isAfter(at) }.maxOrNull() ?: continue
            total++
            if (Duration.between(latest, at).toDays() <= config.deployMaxAgeDays) upToDate++
        }
        return upToDate to total
    }

    private fun maintenanceColor(upToDate: Int, total: Int): SecurityStatusColor =
        when {
            total == 0 || upToDate == total -> SecurityStatusColor.GREEN
            upToDate.toDouble() / total >= config.maintenanceYellowRatio -> SecurityStatusColor.YELLOW
            else -> SecurityStatusColor.RED
        }

    private fun overdueRebuilds(workloads: List<WorkloadFact>, now: Instant): List<AppOverdueRebuild> =
        workloads
            .filter { it.removedAt == null }
            .mapNotNull { workload ->
                val latest = workload.deployments.maxOrNull() ?: return@mapNotNull null
                val daysOver = Duration.between(latest, now).toDays() - config.deployMaxAgeDays
                if (daysOver > 0) AppOverdueRebuild(workload.appName, daysOver.toInt()) else null
            }
            .sortedWith(compareByDescending<AppOverdueRebuild> { it.daysOver }.thenBy { it.app })

    private fun level(offTrack: List<Boolean>, reds: Int, dates: List<LocalDate>, today: LocalDate): SecurityLevel? {
        if (!offTrack.last()) return null
        val runStart = dates[runStartIndex(offTrack)]
        if (reds == 3 || !runStart.plusMonths(config.levelChronicMonths).isAfter(today)) return SecurityLevel.CHRONIC
        val workdays = generateSequence(runStart) { it.plusDays(1) }
            .takeWhile { !it.isAfter(today) }
            .count { it.dayOfWeek != DayOfWeek.SATURDAY && it.dayOfWeek != DayOfWeek.SUNDAY }
        return if (reds >= 2 || workdays >= config.levelNewWorkdays) SecurityLevel.ONGOING else SecurityLevel.NEW
    }

    private fun since(colors: List<SecurityStatusColor>, dates: List<LocalDate>): String? {
        if (colors.last() == SecurityStatusColor.GREEN) return null
        val start = runStartIndex(colors.map { it != SecurityStatusColor.GREEN })
        return iso(dates[start].atStartOfDay(zone).toInstant())
    }

    private fun runStartIndex(flags: List<Boolean>): Int {
        var i = flags.size - 1
        while (i > 0 && flags[i - 1]) i--
        return i
    }

    private fun firstIndex(from: Int, to: Int, predicate: (Int) -> Boolean): Int {
        var lo = from
        var hi = to
        while (lo < hi) {
            val mid = (lo + hi) ushr 1
            if (predicate(mid)) hi = mid else lo = mid + 1
        }
        return lo
    }

    private fun iso(instant: Instant): String = DateTimeFormatter.ISO_INSTANT.format(instant)
}
