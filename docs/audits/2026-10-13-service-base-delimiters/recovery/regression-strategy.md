# PR61 için dar endpoint regresyon stratejisi

BASE: `1caae328fe73a5ab96bb4200d5e28d926807d201`, tree `36615324cc626e7cdc84553fd19c706d9c00a4be`, source 378/678a. Exact Git kopyaları, üç join expression ve native compile/function hashes bu yeni recovery klasöründe. PR60 ve önceki evidence dosyaları değiştirilmedi.

Before ölçümü: POST ile gateway/prover GET caller-join seam’lerinin her birinde normal `/base/`, query `/base?x=1`, fragment `/base#note`, boş query `/base?` denendi. Toplam 12 gerçek owned loopback request, her vaka 1 request. Normal `/base/prove` veya `/base/attest`; query `/base?x=1/prove|attest`; fragment `/base`; boş query `/base?/prove|attest`. Peer’ın 200/valid JSON yanıtı düşük seviyede OK oldu. Bu gerçek handshake/attestation/proof/backend veya servis acceptance değildir. GET seams, exact caller join expression’ın ardından exact GET fonksiyonunu çağırdı; bütün boot/handshake fonksiyonları/private env/collateral çalıştırılmadı.

Önerilen pure-std `service_endpoint(base,suffix)` yalnız raw `?` veya `#` için static `Error::Endpoint` üretmeli; mevcut `trim_end_matches('/')` ve sabit suffix join aynı kalmalı. Scheme/authority/userinfo/normalize/body cap/new dependency policy bu pakette seçilmemeli. Mevcut scheme-less, encoded `%3F/%23`, IPv6 ve path prefix uyumluluğu korunmalı. Suffix yalnız mevcut sabit `prove`/`attest` caller değerleri; başka suffix politikası eklenmemeli.

Anlamlı kabul vakaları:

1. Pure helper: normal empty/root/nested path, bir veya birden çok son slash aynı legacy join sonucu; encoded `%3F/%23` literal path; scheme-less, HTTP(S), IPv6 adres stringleri önceki şekilde join edilir. Raw query boş `?` dahil, raw fragment boş `#` dahil `Error::Endpoint`; hata configured URL’yi açıklamaz.
2. Gerçek POST caller: aynı native 160 KiB control 1 request/200/JSON; query, fragment ve empty delimiter BASE artık error ve 0 request. Marker yazan owned injected command ile bu hatalarda child spawn olmadığını kanıtla; nonexistent executable sonucu ile yalnız network yokluğunu karıştırma. Deadline invalid/input error precedence var olan timeout kuralını bozmasın.
3. İki GET caller: base-builder `service_endpoint(...,attest)` seam’i, ardından exact `http_get_json_command`; bad BASE için marker0/request0, iyi `/base/` için tek native `/base/attest`. Bütün gerçek handshake’i çalıştırmak gereksiz ve env/credential/quote gerektirir. Callsite mapping’i kaynak assertion/derleme ile bağla; GET funcs halen byte-identical olmalı.
4. Doğrudan tam URL alan GET helper pozitif query kontrolü: owned `http://127.0.0.1:port/attest?owned=1` bir request ile geçmeli. Bu interface query’yi genel olarak reddetmemeli; ret yalnız service BASE builder’da.
5. Önceki brace/range literal one-transfer ve HTTP(S)-only curl policy, normal 401 typed Unauthorized/tek rehandshake, response/stdout/stderr/deadline bounds ve timeout/status parsing testleri aynı kriterlerle geçmeli.
6. Aynı exact-source native harness after fresh klasörde replay edilebilir: kontrol ve bad BASE vaka/payload’ları aynı, beklenen bad sonuç low-level OK/1request→Endpoint/0request. No child marker + zero request ayrı kanıtlar. Accepted stream blocking ayarı ve fixture socket deadlines korunmalı.

Bu task yalnız before reproduction ve strateji. Source/Git edit yok. Operatör tarafından yapılandırılan BASE için misrouting bug’ıdır; untrusted-peer credential forgery veya proof kabulü gösterilmedi.
