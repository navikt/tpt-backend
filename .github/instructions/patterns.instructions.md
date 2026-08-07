---
applyTo: "src/main/**/*.kt"
---

# Common Patterns

We follow best practices from the Kotlin foundation and Ktor documentation.

## Use Case Pattern

```kotlin
class GenerateCodeImageUseCase(
    private val highlighterService: CodeHighlighterService,
    private val rendererFactory: ImageRendererFactory
) {
    suspend fun execute(request: GenerateImageRequest): ByteArray {
        // Business logic here
    }
}
```

## Factory Pattern

```kotlin
class ImageRendererFactory {
    fun createRenderer(designSystem: String): ImageRenderer = when (designSystem) {
        "material" -> MaterialDesignImageRenderer()
        "macos" -> Java2DImageRenderer()
        else -> Java2DImageRenderer() // default
    }
}
```

## Leader Election Pattern

**CRITICAL: Every background sync job MUST call `leaderElection.startLeaderElectionChecks(this)` at startup.**
Without it, `cachedLeaderStatus` defaults to `false` and leader-gated operations silently never run. The call is idempotent (safe to call from multiple sync jobs).

```kotlin
fun Application.configureMySync() {
    val leaderElection = dependencies.leaderElection
    leaderElection.startLeaderElectionChecks(this) // REQUIRED — must be called in every sync job

    launch {
        while (true) {
            leaderElection.ifLeader { doWork() } // only runs on the elected leader pod
            delay(interval)
        }
    }
}
```

`ifLeader { }` uses a cached status polled every 60s via the Kubernetes elector sidecar (`ELECTOR_GET_URL`). When the env var is absent (local dev), the pod assumes it is the leader.
