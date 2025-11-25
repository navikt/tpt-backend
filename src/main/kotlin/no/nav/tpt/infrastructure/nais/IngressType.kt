package no.nav.tpt.infrastructure.nais

enum class IngressType {
    UNKNOWN,
    EXTERNAL,
    INTERNAL,
    AUTHENTICATED;

    companion object {
        fun fromString(value: String): IngressType {
            return entries.find { it.name.equals(value, ignoreCase = true) } ?: UNKNOWN
        }
    }
}

