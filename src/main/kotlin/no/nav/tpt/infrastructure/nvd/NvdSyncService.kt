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

        while (currentStart.isBefore(now)) {
            val currentEnd = currentStart.plusDays(daysPerChunk.toLong()).let {
                if (it.isAfter(now)) now else it
            }

            chunkNumber++
            logger.info("Syncing CVEs chunk $chunkNumber: ${currentStart.toLocalDate()} to ${currentEnd.toLocalDate()}")

            val cvesInChunk = syncPublishedDateRange(currentStart, currentEnd)
            totalCvesProcessed += cvesInChunk

            // Respect rate limits: 6 seconds between requests (safe for both free and paid tiers)
            delay(6000)

            currentStart = currentEnd.plusSeconds(1)
        }

        logger.info("Initial NVD sync completed successfully after $chunkNumber chunks. Total CVEs: $totalCvesProcessed")
    }

    suspend fun performIncrementalSync() {
        val lastModified = repository.getLastModifiedDate()
            ?: LocalDateTime.now().minusDays(7) // Default: last 7 days if no data

        val now = LocalDateTime.now()

        logger.info("Performing incremental sync for CVEs modified between $lastModified and $now")
        val cvesProcessed = syncDateRange(lastModified, now)
        logger.info("Incremental sync completed. Processed $cvesProcessed CVEs")
    }

    suspend fun syncDateRange(startDate: LocalDateTime, endDate: LocalDateTime): Int {
        var startIndex = 0
        val resultsPerPage = 2000 // Max allowed by NVD API
        var totalProcessed = 0

        do {
            try {
                val response = nvdClient.getCvesByModifiedDate(
                    lastModStartDate = startDate,
                    lastModEndDate = endDate,
                    startIndex = startIndex,
                    resultsPerPage = resultsPerPage
                )

                // If no results at all, break immediately (nothing to sync in this range)
                if (response.totalResults == 0) {
                    logger.info("No CVEs found in date range ${startDate.toLocalDate()} to ${endDate.toLocalDate()}")
                    break
                }

                if (response.vulnerabilities.isNotEmpty()) {
                    val cveDataList = response.vulnerabilities
                        .map { it.cve }
                        .map { nvdClient.mapToNvdCveData(it) }

                    repository.upsertCves(cveDataList)
                    totalProcessed += cveDataList.size
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
                logger.error("Error syncing CVEs at index $startIndex", e)
                throw e
            }

        } while (true)

        return totalProcessed
    }

    suspend fun syncPublishedDateRange(startDate: LocalDateTime, endDate: LocalDateTime): Int {
        var startIndex = 0
        val resultsPerPage = 2000 // Max allowed by NVD API
        var totalProcessed = 0

        do {
            try {
                val response = nvdClient.getCvesByPublishedDate(
                    pubStartDate = startDate,
                    pubEndDate = endDate,
                    startIndex = startIndex,
                    resultsPerPage = resultsPerPage
                )

                // If no results at all, break immediately (nothing to sync in this range)
                if (response.totalResults == 0) {
                    logger.info("No CVEs found published in date range ${startDate.toLocalDate()} to ${endDate.toLocalDate()}")
                    break
                }

                if (response.vulnerabilities.isNotEmpty()) {
                    val cveDataList = response.vulnerabilities
                        .map { it.cve }
                        .map { nvdClient.mapToNvdCveData(it) }

                    repository.upsertCves(cveDataList)
                    totalProcessed += cveDataList.size
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
                logger.error("Error syncing CVEs at index $startIndex", e)
                throw e
            }

        } while (true)

        return totalProcessed
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

