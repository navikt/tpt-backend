package no.nav.tpt.infrastructure.gcve

import kotlinx.serialization.json.Json
import kotlin.test.*

class GcveModelsTest {

    private val json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
        coerceInputValues = true
    }

    @Test
    fun `should deserialize CVE v5 1 response with SSVC and KEV in ADP container`() {
        val response = json.decodeFromString<GcveCveRecord>(LOG4J_RESPONSE)

        assertEquals("CVE_RECORD", response.dataType)
        assertEquals("5.1", response.dataVersion)
        assertEquals("CVE-2021-44228", response.cveMetadata.cveId)
        assertEquals("PUBLISHED", response.cveMetadata.state)
        assertEquals("2021-12-10T00:00:00.000Z", response.cveMetadata.datePublished)
        assertEquals("2025-10-21T23:25:23.121Z", response.cveMetadata.dateUpdated)

        val cna = response.containers.cna
        assertNotNull(cna)
        assertEquals("Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints", cna.title)
        assertTrue(cna.descriptions.any { it.lang == "en" && it.value.contains("Log4j2") })

        val cweIds = cna.problemTypes?.flatMap { it.descriptions }?.mapNotNull { it.cweId } ?: emptyList()
        assertTrue(cweIds.contains("CWE-502"))
        assertTrue(cweIds.contains("CWE-400"))

        assertTrue(cna.references.isNotEmpty())
        assertTrue(cna.references.any { it.url.contains("logging.apache.org") })

        val adpContainers = response.containers.adp ?: emptyList()
        assertTrue(adpContainers.isNotEmpty())

        val cisaAdp = adpContainers.find { it.providerMetadata?.shortName == "CISA-ADP" }
        assertNotNull(cisaAdp, "CISA-ADP container should be present")

        val cvss = cisaAdp.metrics?.mapNotNull { it.cvssV3_1 }?.firstOrNull()
        assertNotNull(cvss, "CVSS v3.1 should be present in CISA-ADP container")
        assertEquals(10.0, cvss.baseScore)
        assertEquals("CRITICAL", cvss.baseSeverity)
        assertEquals("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", cvss.vectorString)

        val ssvc = cisaAdp.metrics?.mapNotNull { it.other }?.find { it.type == "ssvc" }
        assertNotNull(ssvc, "SSVC metric should be present")
        val ssvcContent = ssvc.content
        assertNotNull(ssvcContent)
        assertEquals("CVE-2021-44228", ssvcContent.id)
        val options = ssvcContent.options ?: emptyList()
        assertTrue(options.any { it.containsKey("Exploitation") && it["Exploitation"] == "active" })
        assertTrue(options.any { it.containsKey("Automatable") && it["Automatable"] == "yes" })
        assertTrue(options.any { it.containsKey("Technical Impact") && it["Technical Impact"] == "total" })

        val kev = cisaAdp.metrics?.mapNotNull { it.other }?.find { it.type == "kev" }
        assertNotNull(kev, "KEV metric should be present")
        val kevContent = kev.content
        assertNotNull(kevContent)
        assertEquals("2021-12-10", kevContent.dateAdded)
    }

    @Test
    fun `should deserialize CVE v5 2 response with CNA-provided CVSS`() {
        val response = json.decodeFromString<GcveCveRecord>(XZ_RESPONSE)

        assertEquals("CVE_RECORD", response.dataType)
        assertEquals("5.2", response.dataVersion)
        assertEquals("CVE-2024-3094", response.cveMetadata.cveId)
        assertEquals("PUBLISHED", response.cveMetadata.state)
        assertEquals("2024-03-29T16:51:12.588Z", response.cveMetadata.datePublished)

        val cna = response.containers.cna
        assertNotNull(cna)
        assertTrue(cna.descriptions.any { it.lang == "en" && it.value.contains("xz") })

        val cnaMetrics = cna.metrics ?: emptyList()
        val cnaCvss = cnaMetrics.mapNotNull { it.cvssV3_1 }.firstOrNull()
        assertNotNull(cnaCvss, "CNA should provide CVSS v3.1")
        assertEquals(10.0, cnaCvss.baseScore)

        val cweIds = cna.problemTypes?.flatMap { it.descriptions }?.mapNotNull { it.cweId } ?: emptyList()
        assertTrue(cweIds.contains("CWE-506"))

        val cisaAdp = response.containers.adp?.find { it.providerMetadata?.shortName == "CISA-ADP" }
        assertNotNull(cisaAdp)
        val ssvc = cisaAdp.metrics?.mapNotNull { it.other }?.find { it.type == "ssvc" }
        assertNotNull(ssvc)
        val options = ssvc.content?.options ?: emptyList()
        assertTrue(options.any { it.containsKey("Exploitation") && it["Exploitation"] == "none" })
        assertTrue(options.any { it.containsKey("Automatable") && it["Automatable"] == "yes" })
        assertTrue(options.any { it.containsKey("Technical Impact") && it["Technical Impact"] == "total" })
    }

    @Test
    fun `should deserialize CVE with CVSS v4 0 score`() {
        val response = json.decodeFromString<GcveCveRecord>(CVSS_V4_RESPONSE)

        assertEquals("CVE-2026-54431", response.cveMetadata.cveId)

        val cna = response.containers.cna
        assertNotNull(cna)

        val cnaMetrics = cna.metrics ?: emptyList()
        val cvssV4 = cnaMetrics.mapNotNull { it.cvssV4_0 }.firstOrNull()
        assertNotNull(cvssV4, "CVSS v4.0 should be present")
        assertEquals(5.1, cvssV4.baseScore)
        assertEquals("MEDIUM", cvssV4.baseSeverity)
        assertTrue(cvssV4.vectorString.startsWith("CVSS:4.0/"))
    }

    @Test
    fun `should deserialize list endpoint response as array`() {
        val records = json.decodeFromString<List<GcveCveRecord>>(LIST_RESPONSE)

        assertEquals(2, records.size)
        assertEquals("CVE-2026-54431", records[0].cveMetadata.cveId)
        assertEquals("CVE-2026-54430", records[1].cveMetadata.cveId)
    }

    @Test
    fun `should deserialize EPSS response`() {
        val response = json.decodeFromString<GcveEpssResponse>(EPSS_RESPONSE)

        assertEquals("OK", response.status)
        assertEquals(200, response.statusCode)
        assertEquals(1, response.total)
        assertEquals(1, response.data.size)
        assertEquals("CVE-2021-44228", response.data[0].cve)
        assertEquals("0.99999", response.data[0].epss)
        assertEquals("1.0", response.data[0].percentile)
        assertEquals("2026-07-01", response.data[0].date)
    }

    @Test
    fun `should handle missing optional fields gracefully`() {
        val minimalJson = """
            {
                "dataType": "CVE_RECORD",
                "dataVersion": "5.1",
                "cveMetadata": {
                    "cveId": "CVE-2024-0001",
                    "state": "PUBLISHED",
                    "assignerOrgId": "test-org"
                },
                "containers": {
                    "cna": {
                        "providerMetadata": {
                            "orgId": "test-org"
                        },
                        "descriptions": [
                            {"lang": "en", "value": "Test description"}
                        ],
                        "affected": [],
                        "references": []
                    }
                }
            }
        """.trimIndent()

        val record = json.decodeFromString<GcveCveRecord>(minimalJson)
        assertEquals("CVE-2024-0001", record.cveMetadata.cveId)
        assertNull(record.cveMetadata.datePublished)
        assertNull(record.cveMetadata.dateUpdated)
        assertNull(record.containers.adp)
        assertNull(record.containers.cna.title)
        assertNull(record.containers.cna.metrics)
        assertNull(record.containers.cna.problemTypes)
        assertTrue(record.containers.cna.references.isEmpty())
    }

    @Test
    fun `should map GCVE record to domain model`() {
        val record = json.decodeFromString<GcveCveRecord>(LOG4J_RESPONSE)
        val domainModel = GcveCveRecord.toDomainModel(record)

        assertEquals("CVE-2021-44228", domainModel.cveId)
        assertTrue(domainModel.description?.contains("Log4j2") == true)
        assertEquals(10.0, domainModel.cvssV31Score)
        assertEquals("CRITICAL", domainModel.cvssV31Severity)
        assertEquals("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", domainModel.cvssV31Vector)
        assertTrue(domainModel.cweIds.contains("CWE-502"))
        assertTrue(domainModel.references.isNotEmpty())
        assertNotNull(domainModel.publishedDate)
        assertNotNull(domainModel.lastUpdatedDate)

        assertEquals("active", domainModel.ssvcExploitation)
        assertEquals("yes", domainModel.ssvcAutomatable)
        assertEquals("total", domainModel.ssvcTechnicalImpact)

        assertTrue(domainModel.hasKevEntry)
        assertEquals("2021-12-10", domainModel.kevDateAdded)
    }

    @Test
    fun `should map GCVE record with CNA-only CVSS when no ADP CVSS present`() {
        val record = json.decodeFromString<GcveCveRecord>(XZ_RESPONSE)
        val domainModel = GcveCveRecord.toDomainModel(record)

        assertEquals("CVE-2024-3094", domainModel.cveId)
        assertEquals(10.0, domainModel.cvssV31Score)
        assertEquals("CRITICAL", domainModel.cvssV31Severity)
        assertEquals("none", domainModel.ssvcExploitation)
        assertEquals("yes", domainModel.ssvcAutomatable)
        assertEquals("total", domainModel.ssvcTechnicalImpact)
        assertFalse(domainModel.hasKevEntry)
    }

    @Test
    fun `should map GCVE record with CVSS v4 0`() {
        val record = json.decodeFromString<GcveCveRecord>(CVSS_V4_RESPONSE)
        val domainModel = GcveCveRecord.toDomainModel(record)

        assertEquals("CVE-2026-54431", domainModel.cveId)
        assertEquals(5.1, domainModel.cvssV40Score)
        assertEquals("MEDIUM", domainModel.cvssV40Severity)
        assertNull(domainModel.cvssV31Score)
    }

    @Test
    fun `should extract data provenance from CNA provider`() {
        val record = json.decodeFromString<GcveCveRecord>(LOG4J_RESPONSE)
        val domainModel = GcveCveRecord.toDomainModel(record)

        assertEquals("apache", domainModel.cnaSource)
    }

    companion object {
        val LOG4J_RESPONSE = """
            {
                "dataType": "CVE_RECORD",
                "dataVersion": "5.1",
                "cveMetadata": {
                    "state": "PUBLISHED",
                    "cveId": "CVE-2021-44228",
                    "assignerOrgId": "f0158376-9dc2-43b6-827c-5f631a4d8d09",
                    "assignerShortName": "apache",
                    "dateUpdated": "2025-10-21T23:25:23.121Z",
                    "dateReserved": "2021-11-26T00:00:00.000Z",
                    "datePublished": "2021-12-10T00:00:00.000Z"
                },
                "containers": {
                    "cna": {
                        "title": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints",
                        "providerMetadata": {
                            "orgId": "f0158376-9dc2-43b6-827c-5f631a4d8d09",
                            "shortName": "apache",
                            "dateUpdated": "2023-04-03T00:00:00.000Z"
                        },
                        "descriptions": [
                            {"lang": "en", "value": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints."}
                        ],
                        "affected": [
                            {"vendor": "Apache Software Foundation", "product": "Apache Log4j2", "versions": [{"version": "2.0-beta9", "status": "affected"}]}
                        ],
                        "references": [
                            {"url": "https://logging.apache.org/log4j/2.x/security.html"},
                            {"url": "http://www.openwall.com/lists/oss-security/2021/12/10/1", "tags": ["mailing-list"]}
                        ],
                        "metrics": [
                            {"other": {"type": "unknown", "content": {"other": "critical"}}}
                        ],
                        "problemTypes": [
                            {"descriptions": [{"type": "CWE", "lang": "en", "description": "CWE-502 Deserialization of Untrusted Data", "cweId": "CWE-502"}]},
                            {"descriptions": [{"type": "CWE", "lang": "en", "description": "CWE-400 Uncontrolled Resource Consumption", "cweId": "CWE-400"}]},
                            {"descriptions": [{"type": "CWE", "lang": "en", "description": "CWE-20 Improper Input Validation", "cweId": "CWE-20"}]}
                        ]
                    },
                    "adp": [
                        {
                            "providerMetadata": {"orgId": "af854a3a-2127-422b-91ae-364da2661108", "shortName": "CVE", "dateUpdated": "2024-08-04T04:17:24.696Z"},
                            "title": "CVE Program Container",
                            "references": [
                                {"url": "https://logging.apache.org/log4j/2.x/security.html", "tags": ["x_transferred"]}
                            ]
                        },
                        {
                            "metrics": [
                                {"cvssV3_1": {"scope": "CHANGED", "version": "3.1", "baseScore": 10.0, "attackVector": "NETWORK", "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "integrityImpact": "HIGH", "userInteraction": "NONE", "attackComplexity": "LOW", "availabilityImpact": "HIGH", "privilegesRequired": "NONE", "confidentialityImpact": "HIGH"}},
                                {"other": {"type": "ssvc", "content": {"id": "CVE-2021-44228", "role": "CISA Coordinator", "options": [{"Exploitation": "active"}, {"Automatable": "yes"}, {"Technical Impact": "total"}], "version": "2.0.3", "timestamp": "2025-02-04T14:25:34.416117Z"}}},
                                {"other": {"type": "kev", "content": {"dateAdded": "2021-12-10", "reference": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-44228"}}}
                            ],
                            "title": "CISA ADP Vulnrichment",
                            "providerMetadata": {"orgId": "134c704f-9b21-4f2e-91b3-4a467353bcc0", "shortName": "CISA-ADP", "dateUpdated": "2025-10-21T23:25:23.121Z"}
                        }
                    ]
                }
            }
        """.trimIndent()

        val XZ_RESPONSE = """
            {
                "dataType": "CVE_RECORD",
                "dataVersion": "5.2",
                "cveMetadata": {
                    "cveId": "CVE-2024-3094",
                    "assignerOrgId": "53f830b8-0a3f-465b-8143-3b8a9948e749",
                    "state": "PUBLISHED",
                    "assignerShortName": "redhat",
                    "dateReserved": "2024-03-29T15:38:13.249Z",
                    "datePublished": "2024-03-29T16:51:12.588Z",
                    "dateUpdated": "2025-11-20T07:17:48.594Z"
                },
                "containers": {
                    "cna": {
                        "title": "Xz: malicious code in distributed source",
                        "providerMetadata": {
                            "orgId": "53f830b8-0a3f-465b-8143-3b8a9948e749",
                            "shortName": "redhat",
                            "dateUpdated": "2025-11-20T07:17:48.594Z"
                        },
                        "descriptions": [
                            {"lang": "en", "value": "Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0."}
                        ],
                        "affected": [
                            {"versions": [{"status": "affected", "version": "5.6.0"}], "packageName": "xz", "collectionURL": "https://github.com/tukaani-project/xz", "defaultStatus": "unaffected"}
                        ],
                        "references": [
                            {"url": "https://access.redhat.com/security/cve/CVE-2024-3094", "tags": ["vdb-entry"]},
                            {"url": "https://www.openwall.com/lists/oss-security/2024/03/29/4"}
                        ],
                        "metrics": [
                            {"cvssV3_1": {"attackComplexity": "LOW", "attackVector": "NETWORK", "availabilityImpact": "HIGH", "baseScore": 10.0, "baseSeverity": "CRITICAL", "confidentialityImpact": "HIGH", "integrityImpact": "HIGH", "privilegesRequired": "NONE", "scope": "CHANGED", "userInteraction": "NONE", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "version": "3.1"}, "format": "CVSS"}
                        ],
                        "problemTypes": [
                            {"descriptions": [{"cweId": "CWE-506", "description": "Embedded Malicious Code", "lang": "en", "type": "CWE"}]}
                        ]
                    },
                    "adp": [
                        {
                            "metrics": [
                                {"other": {"type": "ssvc", "content": {"timestamp": "2024-04-02T04:00:23.138684Z", "id": "CVE-2024-3094", "options": [{"Exploitation": "none"}, {"Automatable": "yes"}, {"Technical Impact": "total"}], "role": "CISA Coordinator", "version": "2.0.3"}}}
                            ],
                            "title": "CISA ADP Vulnrichment",
                            "providerMetadata": {"orgId": "134c704f-9b21-4f2e-91b3-4a467353bcc0", "shortName": "CISA-ADP", "dateUpdated": "2024-07-30T15:37:17.662Z"}
                        }
                    ]
                }
            }
        """.trimIndent()

        val CVSS_V4_RESPONSE = """
            {
                "dataType": "CVE_RECORD",
                "dataVersion": "5.2",
                "cveMetadata": {
                    "cveId": "CVE-2026-54431",
                    "assignerOrgId": "4bb8329e-dd38-46c1-aafb-9bf32bcb93c6",
                    "state": "PUBLISHED",
                    "assignerShortName": "CERT-PL",
                    "dateReserved": "2026-06-15T13:08:01.057Z",
                    "datePublished": "2026-07-02T10:30:57.655Z",
                    "dateUpdated": "2026-07-02T12:13:33.033Z"
                },
                "containers": {
                    "cna": {
                        "providerMetadata": {"orgId": "4bb8329e-dd38-46c1-aafb-9bf32bcb93c6", "shortName": "CERT-PL", "dateUpdated": "2026-07-02T10:44:44.691Z"},
                        "title": "Improper Data Validation in liboauth2",
                        "descriptions": [
                            {"lang": "en", "value": "In liboauth2 the DPoP verifier accepts a proof whose JWK header contains private key material."}
                        ],
                        "affected": [
                            {"vendor": "OpenIDC", "product": "liboauth2", "versions": [{"status": "affected", "version": "0", "lessThan": "2.3.0", "versionType": "semver"}], "defaultStatus": "unaffected"}
                        ],
                        "references": [
                            {"url": "https://cert.pl/en/posts/2026/07/CVE-2026-54430", "tags": ["third-party-advisory"]}
                        ],
                        "metrics": [
                            {"format": "CVSS", "cvssV4_0": {"attackVector": "LOCAL", "attackComplexity": "LOW", "attackRequirements": "NONE", "privilegesRequired": "NONE", "userInteraction": "NONE", "vulnConfidentialityImpact": "LOW", "vulnIntegrityImpact": "NONE", "vulnAvailabilityImpact": "NONE", "version": "4.0", "baseSeverity": "MEDIUM", "baseScore": 5.1, "vectorString": "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"}}
                        ],
                        "problemTypes": [
                            {"descriptions": [{"lang": "en", "cweId": "CWE-358", "description": "CWE-358 Improperly Implemented Security Check for Standard", "type": "CWE"}]}
                        ]
                    },
                    "adp": [
                        {
                            "metrics": [
                                {"other": {"type": "ssvc", "content": {"timestamp": "2026-07-02T12:13:26.177186Z", "id": "CVE-2026-54431", "options": [{"Exploitation": "none"}, {"Automatable": "yes"}, {"Technical Impact": "partial"}], "role": "CISA Coordinator", "version": "2.0.3"}}}
                            ],
                            "title": "CISA ADP Vulnrichment",
                            "providerMetadata": {"orgId": "134c704f-9b21-4f2e-91b3-4a467353bcc0", "shortName": "CISA-ADP", "dateUpdated": "2026-07-02T12:13:33.033Z"}
                        }
                    ]
                }
            }
        """.trimIndent()

        val LIST_RESPONSE = """
            [
                $CVSS_V4_RESPONSE,
                {
                    "dataType": "CVE_RECORD",
                    "dataVersion": "5.2",
                    "cveMetadata": {
                        "cveId": "CVE-2026-54430",
                        "assignerOrgId": "4bb8329e-dd38-46c1-aafb-9bf32bcb93c6",
                        "state": "PUBLISHED",
                        "assignerShortName": "CERT-PL",
                        "datePublished": "2026-07-02T10:30:33.766Z",
                        "dateUpdated": "2026-07-02T10:45:00.888Z"
                    },
                    "containers": {
                        "cna": {
                            "providerMetadata": {"orgId": "4bb8329e-dd38-46c1-aafb-9bf32bcb93c6", "shortName": "CERT-PL"},
                            "title": "Server-Site Request Forgery in liboauth2",
                            "descriptions": [{"lang": "en", "value": "liboauth2 is vulnerable to SSRF."}],
                            "affected": [],
                            "references": [{"url": "https://cert.pl/en/posts/2026/07/CVE-2026-54430"}],
                            "metrics": [
                                {"format": "CVSS", "cvssV4_0": {"attackVector": "LOCAL", "attackComplexity": "LOW", "version": "4.0", "baseSeverity": "MEDIUM", "baseScore": 5.1, "vectorString": "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:L/SI:N/SA:N"}}
                            ],
                            "problemTypes": [
                                {"descriptions": [{"lang": "en", "cweId": "CWE-918", "description": "CWE-918 Server-Side Request Forgery (SSRF)", "type": "CWE"}]}
                            ]
                        }
                    }
                }
            ]
        """.trimIndent()

        val EPSS_RESPONSE = """
            {
                "status": "OK",
                "status-code": 200,
                "version": "1.0",
                "access": "private",
                "total": 1,
                "offset": 0,
                "limit": 1,
                "data": [{"cve": "CVE-2021-44228", "epss": "0.99999", "percentile": "1.0", "date": "2026-07-01"}]
            }
        """.trimIndent()
    }
}
