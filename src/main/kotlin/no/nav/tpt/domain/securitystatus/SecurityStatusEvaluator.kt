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

    val measurement = SecurityStatusMeasurement(
        deployMaxAgeDays = config.deployMaxAgeDays,
        exposedRedWorkdays = config.exposedRedWorkdays,
        maintenanceYellowRatio = config.maintenanceYellowRatio,
        trendWindowDays = config.trendWindowDays,
        trendStableRatio = config.trendStableRatio,
        historyMonths = config.historyMonths,
        levelNewWorkdays = config.levelNewWorkdays,
        levelChronicMonths = config.levelChronicMonths,
        criticalWorkdays = slaPolicy.config.criticalWorkdays,
        nonCriticalMonths = slaPolicy.config.nonCriticalMonths,
        timeZone = zone.id,
    )

    private fun earliestHistoryDate(today: LocalDate): LocalDate =
        YearMonth.from(today).minusMonths(config.historyMonths - 1).atDay(1)

    fun historyStart(now: Instant): Instant =
        earliestHistoryDate(now.atZone(zone).toLocalDate()).atStartOfDay(zone).toInstant()

    fun evaluate(
        team: String,
        vulnerabilities: List<VulnerabilityLifecycle>,
        workloads: List<WorkloadFact>,
        now: Instant,
    ): TeamSecurityStatus? {
        if (workloads.isEmpty()) return null

        val today = now.atZone(zone).toLocalDate()
        val baseline = workloads.minOf { it.firstSeenAt }
        val startDate = maxOf(baseline.atZone(zone).toLocalDate(), earliestHistoryDate(today))
        val dates = generateSequence(startDate) { it.plusDays(1) }.takeWhile { !it.isAfter(today) }.toList()
        val n = dates.size
        val dayStart = dates.map { it.atStartOfDay(zone).toInstant() }
        val evalAt = dates.map { if (it == today) now else it.plusDays(1).atStartOfDay(zone).toInstant() }

        val exposure = computeExposure(vulnerabilities, dayStart, evalAt, pointInTime = false)
        val monthEndExposure = computeExposure(vulnerabilities, dayStart, evalAt, pointInTime = true)
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
            history = months.map { (month, indices) ->
                val recorded = indices.filter { i -> workloads.any { isPresent(it, evalAt[i]) } }
                val onTrackDays = recorded.count { overall[it] == SecurityStatusColor.GREEN }
                val needsAttentionDays = recorded.count { overall[it] == SecurityStatusColor.YELLOW }
                val actNowDays = recorded.count { overall[it] == SecurityStatusColor.RED }
                val throughDate = dates[indices.last()]
                MonthlySecurityHistory(
                    month = month.toString(),
                    throughDate = throughDate.toString(),
                    onTrackDays = onTrackDays,
                    needsAttentionDays = needsAttentionDays,
                    actNowDays = actNowDays,
                    missingDays = throughDate.dayOfMonth - recorded.size,
                    provisional = month == YearMonth.from(today),
                )
            },
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
                appsWithOverduePerMonth = months.values.map { idx -> monthEndExposure.overdueApps[idx.last()] },
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
        dayStart: List<Instant>,
        evalAt: List<Instant>,
        pointInTime: Boolean,
    ): Exposure {
        val n = evalAt.size
        val overdueDiff = mutableMapOf<String, IntArray>()
        val redDiff = mutableMapOf<String, IntArray>()

        for (vuln in vulnerabilities) {
            val deadline = slaPolicy.evaluate(vuln.severity, vuln.discoveredAt, vuln.discoveredAt).deadline

            for ((periodStart, periodEnd) in activePeriods(vuln)) {
                val overdueFrom = maxOf(periodStart, deadline)
                val start = firstIndex(0, n) { evalAt[it].isAfter(overdueFrom) }
                val end = when {
                    periodEnd == null -> n
                    pointInTime -> firstIndex(0, n) { !evalAt[it].isBefore(periodEnd) }
                    else -> firstIndex(0, n) { !dayStart[it].isBefore(periodEnd) }
                }
                if (start >= end) continue

                overdueDiff.getOrPut(vuln.appNaisId) { IntArray(n + 1) }.also {
                    it[start]++
                    it[end]--
                }
                val redStart = firstIndex(start, end) {
                    val at = if (periodEnd != null && periodEnd.isBefore(evalAt[it])) periodEnd else evalAt[it]
                    slaPolicy.workdaysOverdue(deadline, at) >= config.exposedRedWorkdays
                }
                if (redStart < end) {
                    redDiff.getOrPut(vuln.appNaisId) { IntArray(n + 1) }.also {
                        it[redStart]++
                        it[end]--
                    }
                }
            }
        }

        val overdueApps = IntArray(n)
        val redApps = IntArray(n)
        overdueDiff.values.forEach { accumulate(it, overdueApps) }
        redDiff.values.forEach { accumulate(it, redApps) }
        return Exposure(overdueApps, redApps)
    }

    private fun activePeriods(vuln: VulnerabilityLifecycle): List<Pair<Instant, Instant?>> {
        val periods = mutableListOf<Pair<Instant, Instant?>>()
        var start = vuln.discoveredAt
        for (gap in vuln.gaps.sortedBy { it.resolvedAt }) {
            periods.add(start to gap.resolvedAt)
            start = gap.reappearedAt
        }
        periods.add(start to vuln.resolvedAt)
        return periods
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
                if (!result.isOverdue) null else vuln to slaPolicy.workdaysOverdue(result.deadline, now)
            }
            .groupBy({ it.first.appNaisId }, { it })
            .map { (_, entries) -> AppPastDeadline(entries.first().first.appName, entries.maxOf { it.second }) }
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
        val fixed = vulnerabilities.sumOf { vuln ->
            (vuln.gaps.map { it.resolvedAt } + listOfNotNull(vuln.resolvedAt))
                .count { it.isAfter(windowStart) && !it.isAfter(at) }
        }
        val difference = kotlin.math.abs(new - fixed)
        return when {
            difference <= config.trendStableRatio * maxOf(new, fixed) -> TrendDirection.STABLE
            new > fixed -> TrendDirection.WORSE
            else -> TrendDirection.IMPROVING
        }
    }

    private fun isPresent(workload: WorkloadFact, at: Instant): Boolean {
        if (workload.firstSeenAt.isAfter(at)) return false
        if (workload.removedAt != null && !workload.removedAt.isAfter(at)) return false
        return workload.absences.none { !it.removedAt.isAfter(at) && it.returnedAt.isAfter(at) }
    }

    private fun lastDeployment(workload: WorkloadFact, at: Instant): Instant? =
        if (workload.deployments.isEmpty()) {
            workload.firstSeenAt
        } else {
            workload.deployments.filter { !it.isAfter(at) }.maxOrNull()
        }

    private fun maintenanceAt(workloads: List<WorkloadFact>, at: Instant): Pair<Int, Int> {
        val tracked = workloads.filter { isPresent(it, at) }.mapNotNull { w -> lastDeployment(w, at) }
        val upToDate = tracked.count { Duration.between(it, at).toDays() <= config.deployMaxAgeDays }
        return upToDate to tracked.size
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
                val reference = lastDeployment(workload, now) ?: return@mapNotNull null
                val daysOver = Duration.between(reference, now).toDays() - config.deployMaxAgeDays
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
