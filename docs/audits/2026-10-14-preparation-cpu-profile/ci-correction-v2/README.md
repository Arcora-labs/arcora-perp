# Current corrected source / v2

İlk PR67 head e19ac1d Linux CI’da iki clippy işinde FAILED: Fixture.name yalnız macOS observer’da okunuyordu. Normal platform-independent assert_inputs artık kapalı fixture isimlerini de doğrular. Tek kaynak satırı değişir; warnings suppression veya production/timed-code değişikliği yok. İlk21dosyalık packet ve rawFAIL kayıtları tarihsel olarak korunur; ilk CI kabul edilmez.

Current382source map `dfe3bbed1fd0b5c807096ec9f4588dd263fca5dd9e419cea11cf6460c16b7b14`; freeze_v2 güncel kaynakları bağlar. Corrected source’ta actual release2PASS/0FAIL/0IGNORE+110samples tekrarlandı; format/clippy/CLI ve independent math/byte QA PASS. Yeni-head CI acceptance henüz bu local packet tarafından iddia edilmez.

| Release CPU medyanı (µs/çağrı) | Normal | Rollback/resealed |
|---|---:|---:|
| Snapshot preview kesiti | 59.483 | 31.896 |
| State clone | 0.233 | 0.117 |
| Ek replay + validate | 319.196 | 473.663 |
| Legacy + cached stub | 317.783 | 471.821 |
| Clock + cached stub | 637.833 | 946.850 |

Phase medianları toplanmaz. Bu iki küçük sıfır-withdrawal girdisinde ikinci native replay sonraki inceleme adayıdır; carry-derived-roots uygulanmadı. Full checkpoint/archive IO, gerçek prover/backend, RSS/OOM/throughput/production kapasitesi ölçülmedi. Placeholder preview ve cached synthetic proof sınırlamaları orijinal yöntemle aynıdır. Eski debug/ilkrelease sonuçları yeni-source acceptance yerine kullanılmaz. Release stripping uyarısı rawstderr’de korunur; optimized executable çalışıp110örneği üretti. Candidate submission kapalı; PRODUCTION HOLD.
