package no.nav.tpt.infrastructure.nvd

import kotlinx.coroutines.delay
import org.slf4j.LoggerFactory
import java.time.LocalDateTime

open class NvdSyncService(
    private val nvdClient: NvdClient,
    private val repository: NvdRepository
) {
    private val logger = LoggerFactory.getLogger(NvdSyncService::class.java)

    suspend fun performInitialSync() {
        logger.info("Starting initial NVD sync - downloading entire CVE database from 2002")

        // NVD best practice: Download the entire CVE dataset using published date
        // NVD API has a 120-day limit on date ranges, so we sync in 90-day chunks
        val startDate = LocalDateTime.of(2002, 1, 1, 0, 0)
        val now = LocalDateTime.now()
        val daysPerChunk = 90

        var currentStart = startDate
        var chunkNumber = 0
        var totalCvesProcessed = 0
        var totalCvesAdded = 0
        var failedChunks = 0

        while (currentStart.isBefore(now)) {
            // Calculate end date: start + 90 days, but ensure we don't exceed current time
            val currentEnd = currentStart.plusDays(daysPerChunk.toLong()).let {
                if (it.isAfter(now)) now else it
            }

            chunkNumber++
            logger.info("Syncing CVEs chunk $chunkNumber: ${currentStart.toLocalDate()} to ${currentEnd.toLocalDate()}")

            try {
                val (cvesInChunk, addedCount) = syncPublishedDateRangeWithStats(currentStart, currentEnd)
                totalCvesProcessed += cvesInChunk
                totalCvesAdded += addedCount
                logger.info("Chunk $chunkNumber completed successfully: $cvesInChunk CVEs processed")
            } catch (e: Exception) {
                failedChunks++
                logger.error("Failed to sync chunk $chunkNumber (${currentStart.toLocalDate()} to ${currentEnd.toLocalDate()}). Continuing with next chunk.", e)
                // Continue with next chunk instead of stopping the entire sync
            }

            // Move to next chunk: start right after the current end
            // This ensures no gaps or overlaps in date ranges
            currentStart = currentEnd.plusNanos(1)

            // If the next start is not before now, we're done
            if (!currentStart.isBefore(now)) {
                break
            }

            // Respect rate limits: 6 seconds between requests (safe for both free and paid tiers)
            delay(6000)
        }

        logger.info("Initial NVD sync completed after $chunkNumber chunks. Total CVEs: $totalCvesProcessed (added: $totalCvesAdded). Failed chunks: $failedChunks")

        if (failedChunks > 0) {
            logger.warn("$failedChunks chunks failed during initial sync. Consider re-running the sync to fetch missing data.")
        }
    }

    suspend fun performIncrementalSync() {
        val lastModified = repository.getLastModifiedDate()
            ?: LocalDateTime.now().minusDays(7) // Default: last 7 days if no data

        val now = LocalDateTime.now()

        logger.info("Performing incremental sync for CVEs modified between $lastModified and $now")
        val (cvesProcessed, addedCount, updatedCount) = syncDateRangeWithStats(lastModified, now)
        logger.info("Incremental sync completed. Processed $cvesProcessed CVEs (added: $addedCount, updated: $updatedCount)")
    }

    suspend fun syncDateRange(startDate: LocalDateTime, endDate: LocalDateTime): Int {
        val (processed, _, _) = syncDateRangeWithStats(startDate, endDate)
        return processed
    }

    suspend fun syncDateRangeWithStats(startDate: LocalDateTime, endDate: LocalDateTime): Triple<Int, Int, Int> {
        var startIndex = 0
        val resultsPerPage = 2000 // Max allowed by NVD API
        var totalProcessed = 0
        var totalAdded = 0
        var totalUpdated = 0
        var consecutiveErrors = 0
        val maxConsecutiveErrors = 3

        do {
            try {
                val response = nvdClient.getCvesByModifiedDate(
                    lastModStartDate = startDate,
                    lastModEndDate = endDate,
                    startIndex = startIndex,
                    resultsPerPage = resultsPerPage
                )

                // Reset error counter on success
                consecutiveErrors = 0

                // If no results at all, break immediately (nothing to sync in this range)
                if (response.totalResults == 0) {
                    logger.info("No CVEs found in date range ${startDate.toLocalDate()} to ${endDate.toLocalDate()}")
                    break
                }

                if (response.vulnerabilities.isNotEmpty()) {
                    val cveDataList = response.vulnerabilities
                        .map { it.cve }
                        .map { nvdClient.mapToNvdCveData(it) }

                    val stats = repository.upsertCves(cveDataList)
                    totalProcessed += cveDataList.size
                    totalAdded += stats.added
                    totalUpdated += stats.updated
                }

                logger.info("Processed ${totalProcessed} of ${response.totalResults} CVEs (batch of ${response.vulnerabilities.size})")

                startIndex += resultsPerPage

                // Stop if we've fetched all results
                if (startIndex >= response.totalResults) {
                    break
                }

                // Rate limit: 6 seconds between requests
                // This is safe for both free tier (5 req/30s) and paid tier (50 req/30s)
                delay(6000)

            } catch (e: Exception) {
                consecutiveErrors++
                logger.error("Error syncing CVEs at index $startIndex (attempt $consecutiveErrors/$maxConsecutiveErrors): ${e.message}", e)

                if (consecutiveErrors >= maxConsecutiveErrors) {
                    logger.error("Too many consecutive errors ($maxConsecutiveErrors), aborting this range")
                    throw e
                }

                // Wait longer before retry
                logger.info("Retrying after 30 seconds...")
                delay(30000)
            }

        } while (true)

        return Triple(totalProcessed, totalAdded, totalUpdated)
    }

    suspend fun syncPublishedDateRange(startDate: LocalDateTime, endDate: LocalDateTime): Int {
        val (processed, _) = syncPublishedDateRangeWithStats(startDate, endDate)
        return processed
    }

    suspend fun syncPublishedDateRangeWithStats(startDate: LocalDateTime, endDate: LocalDateTime): Pair<Int, Int> {
        var startIndex = 0
        val resultsPerPage = 2000 // Max allowed by NVD API
        var totalProcessed = 0
        var totalAdded = 0
        var consecutiveErrors = 0
        val maxConsecutiveErrors = 3

        do {
            try {
                val response = nvdClient.getCvesByPublishedDate(
                    pubStartDate = startDate,
                    pubEndDate = endDate,
                    startIndex = startIndex,
                    resultsPerPage = resultsPerPage
                )

                // Reset error counter on success
                consecutiveErrors = 0

                // If no results at all, break immediately (nothing to sync in this range)
                if (response.totalResults == 0) {
                    logger.info("No CVEs found published in date range ${startDate.toLocalDate()} to ${endDate.toLocalDate()}")
                    break
                }

                if (response.vulnerabilities.isNotEmpty()) {
                    val cveDataList = response.vulnerabilities
                        .map { it.cve }
                        .map { nvdClient.mapToNvdCveData(it) }

                    val stats = repository.upsertCves(cveDataList)
                    totalProcessed += cveDataList.size
                    totalAdded += stats.added
                }

                logger.info("Processed ${totalProcessed} of ${response.totalResults} CVEs (batch of ${response.vulnerabilities.size})")

                startIndex += resultsPerPage

                // Stop if we've fetched all results
                if (startIndex >= response.totalResults) {
                    break
                }

                // Rate limit: 6 seconds between requests
                delay(6000)

            } catch (e: Exception) {
                consecutiveErrors++
                logger.error("Error syncing CVEs at index $startIndex (attempt $consecutiveErrors/$maxConsecutiveErrors): ${e.message}", e)

                if (consecutiveErrors >= maxConsecutiveErrors) {
                    logger.error("Too many consecutive errors ($maxConsecutiveErrors), aborting this chunk")
                    throw e
                }

                // Wait longer before retry
                logger.info("Retrying after 30 seconds...")
                delay(30000)
            }

        } while (true)

        return Pair(totalProcessed, totalAdded)
    }

    suspend fun syncSingleCve(cveId: String): NvdCveData? {
        logger.info("Syncing single CVE: $cveId")

        val cveItem = nvdClient.getCveByCveId(cveId) ?: run {
            logger.warn("CVE $cveId not found in NVD")
            return null
        }

        val cveData = nvdClient.mapToNvdCveData(cveItem)
        repository.upsertCve(cveData)

        logger.info("Successfully synced CVE: $cveId")
        return cveData
    }
}

