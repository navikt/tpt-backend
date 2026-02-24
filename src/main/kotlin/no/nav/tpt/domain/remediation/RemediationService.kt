package no.nav.tpt.domain.remediation

import kotlinx.coroutines.flow.Flow

interface RemediationService {
    fun streamRemediation(request: RemediationRequest): Flow<String>
}
