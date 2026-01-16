package no.nav.tpt.infrastructure.kafka

data class KafkaConfig(
    val brokers: String,
    val certificatePath: String,
    val privateKeyPath: String,
    val caPath: String,
    val credstorePassword: String,
    val keystorePath: String,
    val truststorePath: String
) {
    companion object {
        fun fromEnvironment(): KafkaConfig? {
            val brokers = System.getenv("KAFKA_BROKERS") ?: return null
            val certificatePath = System.getenv("KAFKA_CERTIFICATE_PATH") ?: return null
            val privateKeyPath = System.getenv("KAFKA_PRIVATE_KEY_PATH") ?: return null
            val caPath = System.getenv("KAFKA_CA_PATH") ?: return null
            val credstorePassword = System.getenv("KAFKA_CREDSTORE_PASSWORD") ?: return null
            val keystorePath = System.getenv("KAFKA_KEYSTORE_PATH") ?: return null
            val truststorePath = System.getenv("KAFKA_TRUSTSTORE_PATH") ?: return null

            return KafkaConfig(
                brokers = brokers,
                certificatePath = certificatePath,
                privateKeyPath = privateKeyPath,
                caPath = caPath,
                credstorePassword = credstorePassword,
                keystorePath = keystorePath,
                truststorePath = truststorePath
            )
        }
    }
}

