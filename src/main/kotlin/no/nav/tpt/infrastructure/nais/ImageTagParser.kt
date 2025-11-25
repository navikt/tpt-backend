package no.nav.tpt.infrastructure.nais

import java.time.LocalDate
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException

object ImageTagParser {
    private val patterns = listOf(
        "yyyy.MM.dd-HH.mm" to DateTimeFormatter.ofPattern("yyyy.MM.dd-HH.mm"),
        "yyyy.MM.dd_HH.mm" to DateTimeFormatter.ofPattern("yyyy.MM.dd_HH.mm"),
        "yyyy.MM.dd.HHmmss" to DateTimeFormatter.ofPattern("yyyy.MM.dd.HHmmss")
    )

    fun extractBuildDate(imageTag: String): LocalDate? {
        for ((patternStr, formatter) in patterns) {
            val regex = when {
                patternStr.contains("-HH.mm") -> Regex("""^(\d{4}\.\d{2}\.\d{2}-\d{2}\.\d{2})""")
                patternStr.contains("_HH.mm") -> Regex("""^(\d{4}\.\d{2}\.\d{2}_\d{2}\.\d{2})""")
                patternStr.contains(".HHmmss") -> Regex("""^(\d{4}\.\d{2}\.\d{2}\.\d{6})""")
                else -> continue
            }

            val match = regex.find(imageTag)
            if (match != null) {
                try {
                    return LocalDateTime.parse(match.value, formatter).toLocalDate()
                } catch (_: DateTimeParseException) {
                    continue
                }
            }
        }

        return null
    }
}

