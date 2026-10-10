# Arcora Perp: bağımsız ortamda reviewed guest yeniden üretimi

Tarih: 10 Ekim 2026
PR: #36
İşlevsel commit: `69a1b721c1664a5f293036c621301f52ab21d996`
Başlangıç main: `8d68b5811b9a07c5d6f9d92d946232d33afec719`

## Sonuç

**Reviewed SP1 guest, bağımsız GitHub-hosted ARM64 Mac ortamında boş cache ile
byte-byte yeniden üretildi.** İndirilen ELF için asıl Mac'te yeni CPU setup
çalıştırıldı ve aynı program verification key türetildi. Bu, önceki aynı-makine/
eski registry cache sınırını aşan yeni kanıttır. Production **RELEASE HOLD** sürer.

## Doğrulanan kimlikler

| Kontrol | Sonuç |
|---|---|
| GitHub run | `38050043453`, completed/success |
| İş | cold guest build (macOS ARM64), macos-14, GitHub-hosted |
| Test edilen kaynak SHA | `69a1b721c1664a5f293036c621301f52ab21d996` |
| Synthetic PR merge checkout | `c2222eb4bf6ec8ef793dca24e5386a9cad176a3d` |
| Git tree | `da2a5bc442bca75cb06a6aec9ade0e8650b2ac4c` |
| ELF boyutu | 525824 bayt |
| ELF SHA-256 | `df59a19b310258b4d01d0d5e3cfa31bb7de9ca2f4ea7c2302cf76650c79967c5` |
| Program key | `0x0017893c7ff3395d60b57d25eaa08cf1542fc7bc3cdfd74468133562994b8353` |
| Resmi toolchain arşivi SHA-256 | `8ee4ea0f27efbf73ddfe8a2038ced4c0802fdcf9e1ee109349763b9f4a808cf6` |
| Artifact ZIP SHA-256 | `a739937c1d6497cc7048a0062d411dc2374ec87dec8047924c55829de5aaafda` |

Run adresi: https://github.com/Arcora-labs/arcora-perp/actions/runs/38050043453

GitHub API'deki repository/head/workflow/event/job runner/başarı durumu ayrıca
okundu. Artifact `11668883475` indirildi; ZIP hash'i API digest'iyle,
ELF baytları reviewed fixture ile karşılaştırıldı. Runner-context tek başına
bağımsız makine kanıtı kabul edilmedi. Synthetic merge commit'in iki parent'ı
beklenen main ve PR head; tree'si işlevsel head ile aynı. Derleme script hash'leri,
21 guest kaynak pini ve log hash'leri de eşleşti.

## Tamamlanan değişiklikler

Yeni cold-build runner; resmi, SHA-pinned SP1 derleyici arşivini doğrulayıp açar.
Kullanıcının kurulu SP1 dizinini veya Cargo cache'ini kullanmaz. Ayrı HOME,
CARGO_HOME, TMPDIR ve target oluşturur; kullanıcı config/env/token/profile/wrapper
ayarlarını devralmaz. Önceden mevcut output veya ambient Cargo config'i reddeder.

Locked fetch ile **159 paket arşivi** yeniden indirilir. Sadece lock checksum'ı
değil, arşivden açılmış **5762 kaynak dosyası** da önce/sonra karşılaştırılır.
Ek modül/build script, symlink, değişmiş paket ve eksik/fazla kayıt reddedilir.
Compile `--locked --offline` kullanır. Guest kodu, public input, ELF/vkey pinleri,
sözleşmeler veya ekonomik kurallar değiştirilmedi.

Normalizasyon önceki iki workspace crate metadata'sı, checkout yolu ve yeni Cargo
registry yoluyla sınırlıdır. Dependency metadata'sı korunur. Compiler çağrılarının
asıl ve normalize biçimleri kaydedilir. ELF üzerinde sonradan yama yapılmaz;
fixture derleme output'una kopyalanmaz.

Workflow salt-okuma izni ve cache restore etmeyen macos-14 runner kullanır. Mevcut
11 zorunlu kontrol veya repository review/protection ayarları değiştirilmedi.

## Testler ve tekrar üretim

- 20 yeni guard testi başarılı: env/config izolasyonu, arşiv/compiler checksum,
  archive path sınırı, registry checksum ve açılmış kaynak doğrulaması,
  symlink/ek modül reddi, dar normalizasyon ve başarısız komutun reddi.
- Tüm yerel Python paketi gerçek yerel Anvil dahil **136 PASS, 0 SKIP**.
- Son kaynakla yerel cold build ve bağımsız GitHub cold build başarılı.
- Bağımsız çıktıyı kullanan yeni CPU setup başarılı. Setup host'u mevcut kaynakla
  `cargo +1.99.0 build --release --locked --offline --bin vkey` ile derlendi.
  Host'un gömülü guest build'i atlandı, fakat setup girdisi açık `--elf` ile
  indirilen ve hash'i kontrol edilmiş bağımsız ELF oldu.

Bağımsız runner'da dependency fetch yaklaşık 2.10 saniye,
compile yaklaşık 71.94 saniye sürdü. CPU setup yerelde
15.59 saniye sürdü. Bunlar tekil gözlemdir; **proof süresi,
kapasite p95 veya production finalitesi değildir.**

İlk yerel extraction denemesi resmi arşivdeki hardlink girdilerini gereğinden
dar reddetti. SHA doğrulamasından sonra güvenli tar `data` filtresiyle arşiv-içi
hardlink desteği eklendi; path dışına çıkma kontrolü korunarak sonraki derlemeler
geçti. Bu deneme başarı olarak sayılmadı. Tam Rust workspace/frontend testleri
yerelde bu build-only değişiklik için tekrar koşturulmadı; normal CI ayrıdır.

## Kapanan ve açık kalan kabul ölçütleri

**Kapanan alt ölçüt:** aynı reviewed guest'in başka ARM64 Mac ortamında, resmi
sabit derleyici arşivi ve yeniden indirilen lock-bağlı paketlerle aynı ELF'i
üretmesi. **Ek doğrulama:** o çıktıdan yeni yerel CPU setup ile aynı vkey.

Bu, derleyicinin kaynaktan bağımsız bootstrap edildiğini, Linux/Intel build'inin
aynı olduğunu veya tüm işletim sistemi/linker etkilerinin ortadan kalktığını
kanıtlamaz. Upstream derleyici dağıtımı, Cargo kurulumu, sistem araçları ve
GitHub runner güven sınırlarıdır. Offline Cargo bir ağ sandbox'ı değildir.

Gerçek dört wallet witness için yeni SP1 proof; gerçek verifier/clock/settlement/
claim fon döngüsü; canlı deployment ve servis kimliği; gerçek CC evidence/key
release; farklı makineye snapshot+rollback-journal+L1 cursor kurtarması; ölçülmüş
kapasite/exit/RTO-RPO; oracle, matching fairness ve bağımsız güvenlik incelemesi
açıktır. **R02 canlı deployment kapısı bütünüyle kapanmadı.**

Program key setup'ı asıl Mac'te yapılmıştır; bağımsız runner'da yapıldığı iddia
edilmez. Yeni proof, canlı TEE doğrulaması, state migration veya production
deployment yapılmadı. Bu rapor sonradan docs commit'iyle eklenebilir; işlevsel
kaynakların SHA-256 kayıtları `verification.json` içinde sabittir.

Kullanım: `docs/COLD_GUEST_REBUILD.md`.
Ham yerel kayıtlar: `target/cold-guest-20261010/`.
Kalıcı kanıtlar: bu klasördeki `hosted-provenance.json`, `verification.json`,
`evidence/`. Yayın kopyalarında yalnız asıl kullanıcı home yolu ve satır sonu
boşlukları normalize edildi; ham/yayınlanan hash'ler ayrı kaydedildi.
