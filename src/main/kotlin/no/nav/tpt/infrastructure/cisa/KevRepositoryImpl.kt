package no.nav.tpt.infrastructure.cisa

import kotlinx.coroutines.Dispatchers
import kotlinx.serialization.json.Json
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.SqlExpressionBuilder.eq
import org.jetbrains.exposed.sql.transactions.experimental.newSuspendedTransaction
import org.slf4j.LoggerFactory
import java.time.Instant

class KevRepositoryImpl(private val database: Database) : KevRepository {
    private val logger = LoggerFactory.getLogger(KevRepositoryImpl::class.java)

    private suspend fun <T> dbQuery(block: suspend () -> T): T =
        newSuspendedTransaction(Dispatchers.IO, database) {
            minRetryDelay = 100
            maxRetryDelay = 1000
            maxAttempts = 3
            block()
        }

    override suspend fun getKevCatalog(): KevCatalog? = dbQuery {
        val latestCatalog = KevCatalogMetadata
            .selectAll()
            .orderBy(KevCatalogMetadata.lastUpdated, SortOrder.DESC)
            .limit(1)
            .firstOrNull()
            ?: return@dbQuery null

        val catalogId = latestCatalog[KevCatalogMetadata.id]

        val vulnerabilities = KevVulnerabilities
            .selectAll()
            .where { KevVulnerabilities.catalogId eq catalogId }
            .map { toKevVulnerability(it) }

        KevCatalog(
            title = latestCatalog[KevCatalogMetadata.catalogTitle],
            catalogVersion = latestCatalog[KevCatalogMetadata.catalogVersion],
            dateReleased = latestCatalog[KevCatalogMetadata.dateReleased],
            count = vulnerabilities.size,
            vulnerabilities = vulnerabilities
        )
    }

    override suspend fun getKevForCve(cveId: String): KevVulnerability? = dbQuery {
        KevVulnerabilities
            .selectAll()
            .where { KevVulnerabilities.cveId eq cveId }
            .map { toKevVulnerability(it) }
            .singleOrNull()
    }

    override suspend fun upsertKevCatalog(catalog: KevCatalog) = dbQuery {
        logger.info("Upserting KEV catalog with ${catalog.vulnerabilities.size} vulnerabilities")

        val catalogId = KevCatalogMetadata.insert {
            it[catalogTitle] = catalog.title
            it[catalogVersion] = catalog.catalogVersion
            it[dateReleased] = catalog.dateReleased
            it[vulnerabilityCount] = catalog.count
            it[lastUpdated] = Instant.now()
            it[createdAt] = Instant.now()
        } get KevCatalogMetadata.id

        catalog.vulnerabilities.chunked(100).forEach { chunk ->
            KevVulnerabilities.batchUpsert(
                data = chunk,
                keys = arrayOf(KevVulnerabilities.cveId)
            ) { vuln ->
                this[KevVulnerabilities.cveId] = vuln.cveID
                this[KevVulnerabilities.catalogId] = catalogId
                this[KevVulnerabilities.vendorProject] = vuln.vendorProject
                this[KevVulnerabilities.product] = vuln.product
                this[KevVulnerabilities.vulnerabilityName] = vuln.vulnerabilityName
                this[KevVulnerabilities.dateAdded] = vuln.dateAdded
                this[KevVulnerabilities.shortDescription] = vuln.shortDescription
                this[KevVulnerabilities.requiredAction] = vuln.requiredAction
                this[KevVulnerabilities.dueDate] = vuln.dueDate
                this[KevVulnerabilities.knownRansomwareCampaignUse] = vuln.knownRansomwareCampaignUse
                this[KevVulnerabilities.notes] = vuln.notes
                this[KevVulnerabilities.cwes] = vuln.cwes
                this[KevVulnerabilities.createdAt] = Instant.now()
            }
        }

        deleteOldCatalogs(catalogId)

        logger.info("Successfully upserted KEV catalog (id: $catalogId)")
    }

    override suspend fun isCatalogStale(staleThresholdHours: Int): Boolean = dbQuery {
        val lastUpdated = getLastUpdated() ?: return@dbQuery true
        val staleThreshold = Instant.now().minusSeconds(staleThresholdHours * 3600L)
        lastUpdated < staleThreshold
    }

    override suspend fun getLastUpdated(): Instant? = dbQuery {
        KevCatalogMetadata
            .select(KevCatalogMetadata.lastUpdated)
            .orderBy(KevCatalogMetadata.lastUpdated, SortOrder.DESC)
            .limit(1)
            .firstOrNull()
            ?.get(KevCatalogMetadata.lastUpdated)
    }

    private fun deleteOldCatalogs(currentCatalogId: Int) {
        val oldCatalogIds = KevCatalogMetadata
            .select(KevCatalogMetadata.id)
            .where { KevCatalogMetadata.id neq currentCatalogId }
            .map { it[KevCatalogMetadata.id] }

        if (oldCatalogIds.isNotEmpty()) {
            oldCatalogIds.forEach { id ->
                KevVulnerabilities.deleteWhere { catalogId eq id }
            }
            oldCatalogIds.forEach { id ->
                KevCatalogMetadata.deleteWhere { KevCatalogMetadata.id eq id }
            }
            logger.debug("Deleted ${oldCatalogIds.size} old catalog(s)")
        }
    }

    private fun toKevVulnerability(row: ResultRow): KevVulnerability {
        return KevVulnerability(
            cveID = row[KevVulnerabilities.cveId],
            vendorProject = row[KevVulnerabilities.vendorProject],
            product = row[KevVulnerabilities.product],
            vulnerabilityName = row[KevVulnerabilities.vulnerabilityName],
            dateAdded = row[KevVulnerabilities.dateAdded],
            shortDescription = row[KevVulnerabilities.shortDescription],
            requiredAction = row[KevVulnerabilities.requiredAction],
            dueDate = row[KevVulnerabilities.dueDate],
            knownRansomwareCampaignUse = row[KevVulnerabilities.knownRansomwareCampaignUse],
            notes = row[KevVulnerabilities.notes],
            cwes = row[KevVulnerabilities.cwes]
        )
    }
}
