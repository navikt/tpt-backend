---
applyTo: "src/main/**/*.kt"
---

# Database & Sync Jobs (Kotlin)

## Repository Pattern

```kotlin
interface GcveRepository {
    suspend fun getCveData(cveId: String): GcveCveData?
    suspend fun upsertCves(cves: List<GcveCveData>)
    suspend fun getLastModifiedDate(): LocalDateTime?
}
```

## Database Transaction Pattern

```kotlin
suspend fun <T> dbQuery(block: suspend () -> T): T =
    newSuspendedTransaction(Dispatchers.IO) { block() }

// Batch operations with chunking
suspend fun upsertCves(cves: List<GcveCveData>) {
    cves.chunked(500).forEach { batch ->
        dbQuery {
            batch.forEach { cve ->
                // Upsert logic
            }
        }
    }
}
```

## NVD Sync Strategy

- **Initial Sync**: Year-by-year from 2002 to present (~1-2 hours, leader-only)
- **Incremental Sync**: Every 2 hours using `lastModifiedDate` tracking (leader-only)
- **Leader Election**: Kubernetes native leader election prevents duplicate syncs
- **Date Format**: ISO 8601 with UTC timezone (`2024-01-01T00:00:00.000Z`)
- **Error Handling**: HTTP status checking before response deserialization

## Vulnrichment Sync Strategy

- **Initial Sync**: Fetches from 2023-01-01 on empty database (leader-only), triggered 30s after startup
- **Incremental Sync**: Every 24 hours using `lastUpdated` tracking (leader-only)
- Same leader-election pattern as NVD sync (see `patterns.instructions.md`)

## Vulnerability Team Sync

- Per-team sync (`VulnerabilityTeamSyncService`) upserts vulnerabilities, then sets `resolved_at` on rows that vanished. Rows are never hard-deleted by the sync; resolved rows are purged after the history retention (history months + trend window).
- All "current" queries must filter `resolved_at IS NULL`.
- The same sync records workloads and their latest deployment (`workloads`, `workload_deployments`). `GET /security-status` is computed on the fly from these tables with `SecurityStatusEvaluator`; there is no snapshot table or extra job.

## Performance

- **Database Indexes**: Proper indexes on frequently queried fields
- **Connection Pooling**: HikariCP for efficient database connection management
- **Batch Processing**: Chunked operations for large datasets (e.g., 500 CVEs per batch)
- **Rate Limiting**: Respect external API rate limits (NVD: 6 seconds between requests)
