package no.nav.tpt.domain

enum class DependencyCategory {
    OS_PACKAGE,
    APPLICATION,
    CONTAINER,
    UNKNOWN;

    companion object {
        private val OS_PACKAGE_TYPES = setOf("deb", "rpm", "apk", "apkg")
        private val APPLICATION_TYPES = setOf(
            "npm", "maven", "pypi", "cargo", "golang", "gem", "nuget", "composer",
            "hex", "pub", "swift", "cocoapods", "conan", "conda", "cran",
            "hackage", "luarocks", "mlflow", "qpkg"
        )
        private val CONTAINER_TYPES = setOf("docker", "oci")

        fun fromPurlType(purlType: String?): DependencyCategory = when {
            purlType == null -> UNKNOWN
            purlType.lowercase() in OS_PACKAGE_TYPES -> OS_PACKAGE
            purlType.lowercase() in APPLICATION_TYPES -> APPLICATION
            purlType.lowercase() in CONTAINER_TYPES -> CONTAINER
            else -> UNKNOWN
        }
    }
}
