# Gateway sunucu kurulumu

Bu dizin, gateway'i tek bir Linux sunucuda systemd ile çalıştırmak için gereken
dosyaları tutar: servis birimi, yedekleme ve sağlık izleme zamanlayıcıları, alarm
kancası, env şablonları ve Caddy reverse proxy parçası.

**PRODUCTION RELEASE HOLD.** main'in L1 modu doğrulanmış TDX attestation ve
clock-bound proof üreten bir prover gerektirir ([ACTIVE_WORK](../docs/ACTIVE_WORK.md)
G1/G3/G4). Bu dosyalar o kapıları açmaz. Yalnız kurulumu, yedeklemeyi ve alarmı
tekrarlanabilir hâle getirir.

## Dosyalar

| Dosya | Görev |
|---|---|
| `systemd/darkperp-gateway.service` | Gateway. `darkperp` kullanıcısıyla, `127.0.0.1:8080`'de, `/var/lib/darkperp/state.snap` durumuyla çalışır. Sertleştirilmiştir. 10 dakikada 5 başarısız başlatmadan sonra alarm verir. |
| `systemd/darkperp-backup.{service,timer}` | 30 dakikada bir tutarlı snapshot ve journal yedeği alır ([gateway_backup.py](../scripts/ops/gateway_backup.py)). İsteğe bağlı olarak rsync ile başka makineye kopyalar. |
| `systemd/darkperp-monitor.{service,timer}` | Dakikada bir public sağlık okuması yapar ([gateway_monitor.py](../scripts/ops/gateway_monitor.py)). Ayarlıysa settlement kontratını L1'den doğrudan da okur. |
| `systemd/darkperp-notify@.service` | `OnFailure=` kancası. Tek seferlik, redakte edilmiş olay gönderir ([ops_notify.py](../scripts/ops/ops_notify.py)). |
| `env/gateway.env.example`, `env/ops.env.example` | Yalnız değişken adları. Değerler sunucuda doldurulur, git'e girmez. |
| `caddy/darkperp-gateway.caddy` | TLS, gövde sınırı ve WebSocket geçişi. |

## Kurulum (root)

```sh
useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin darkperp
useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin darkperp-ops

# Binary: main'deki her commit için "gateway release binary" workflow'u
# derler (Ubuntu 24.04 / glibc 2.39); sunucuda derleme gerekmez:
#   gh run download <run-id> -n darkperp-gateway-linux-x86_64 -D dist
#   (cd dist && sha256sum -c darkperp-gateway.sha256)
# dist/service-build-identity.json, çalışan servisin GET /identity yanıtıyla
# karşılaştırılır (docs/PUBLIC_SERVICE_IDENTITY.md).
install -m 0755 dist/darkperp-gateway /usr/local/bin/darkperp-gateway
# Gateway L1 için `cast`, prover ve alarm için `curl` çağırır. ProtectHome=yes
# nedeniyle ~/.foundry görünmez: cast'i /usr/local/bin'e kurun.

install -d -m 0755 /usr/local/lib/darkperp-ops
install -m 0755 scripts/ops/ops_notify.py scripts/ops/gateway_backup.py \
  scripts/ops/gateway_monitor.py /usr/local/lib/darkperp-ops/

install -d -m 0700 /etc/darkperp
install -m 0600 deploy/env/gateway.env.example /etc/darkperp/gateway.env   # sonra doldurun
install -m 0600 deploy/env/ops.env.example /etc/darkperp/ops.env

install -m 0644 deploy/systemd/* /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now darkperp-gateway.service darkperp-backup.timer darkperp-monitor.timer
```

systemd, `EnvironmentFile=` dosyalarını yetkiyi düşürmeden önce root olarak
okur. Bu yüzden `root:root 0600` yeterlidir.

## Alarm modeli

Kanal aynıdır: tek bir ntfy.sh topic'i, gövde yalnız sabit enum alanlarından
oluşur, yönlendirme izlenmez, her olay en fazla 3 kez denenir. Topic adı tek
gizlidir; tahmin edilemez bir ad seçin.

| Kaynak | Olaylar | Ne zaman |
|---|---|---|
| Gateway içi (`ops_alerts.rs`, şema `arcora.ops-alert.v1`) | `settlement_held`, `persistence_failed`, `deposit_halted`, `archive_pressure`, `bond_shortfall`, `unanswerable_challenge`, `challenge_discovery_failed`, `stale_anchor`, `liveness_low`, `permit_gc_stalled`, `engine_close_only`, `admission_cap_reached`, `withdraw_nonce_repaired`, `deposit_blocked_at_cap`, `window_voided`, `clock_recovery_blocked` | Süreç ayaktayken başlangıçta ve toparlanmada birer kez |
| Dış izleyici (şema `arcora.ops-monitor.v1`) | `gateway_unreachable`, `settlement_held`, `deposit_halted`, `settle_stall`; gateway ayaktayken `/api/state` `opsAlerts` içindeki `bond_shortfall`, `unanswerable_challenge`, `challenge_discovery_failed`, `stale_anchor`, `liveness_low`, `permit_gc_stalled`, `engine_close_only`, `admission_cap_reached`, `withdraw_nonce_repaired`, `deposit_blocked_at_cap`, `window_voided`, `clock_recovery_blocked`; L1 okumaları ayarlıysa `liveness_low`, `l1_close_only`, `challenge_unanswered`, `l1_unreachable` | Süreç düşük veya kilitliyken de çalışır |
| `OnFailure=` (`arcora.ops-monitor.v1`) | `gateway_service_failed`, `backup_failed`, `monitor_failed` | Unit failed durumuna geçtiğinde |

`settle_stall`: Mühürlenmiş bir pencere bekliyor (`openWindowId > l1.batchCount`)
ve aynı gecikme `--stall-seconds` (900 s) boyunca sürüyor. L1 yoksa bu kontrol
yapılmaz. Eşik yalnız fixture'larla sınandı; canlı L1 gateway'inde ayrıca
doğrulanmalıdır.

### İzleyicinin doğrudan L1 okumaları

`/etc/darkperp/ops.env` içinde `DARKPERP_L1_RPC` ve `DARKPERP_SETTLEMENT`
birlikte ayarlıysa izleyici settlement kontratını gateway'den bağımsız olarak
Foundry `cast` ile okur. Böylece gateway düşükken de L1 durumunu görür. İkisi de
boşsa davranış öncekiyle aynıdır. Yalnız biri ayarlıysa unit başarısız olur ve
`monitor_failed` gelir.

- Yalnız `cast block-number` ve `cast call` çalışır. Bir çalıştırmadaki bütün
  okumalar aynı bloğa sabitlenir (`--block`). İmza, anahtar ve `cast send` yoktur.
- RPC URL'si sağlayıcı anahtarı taşıyabilir. `cast`'e komut satırından değil,
  yalnız `ETH_RPC_URL` ortam değişkeniyle geçer. Çocuk sürece yalnız `PATH`,
  `ETH_RPC_URL`, `ETH_RPC_TIMEOUT` ve `FOUNDRY_DISABLE_NIGHTLY_WARNING` aktarılır;
  ortamın geri kalanı geçmez. `cast`'in hata çıktısı URL'yi tekrarladığı için
  atılır; günlüğe yalnız sabit satırlar (`L1 read failed`,
  `L1 challenge detail read failed`) yazılır.
- Gateway'in `L1_RPC`'sinden farklı bir sağlayıcı seçin. Tek sağlayıcının
  kesintisi ikisini birden kör etmesin.
- `cast` `/usr/local/bin` altında olmalıdır (`ProtectHome=yes`).

| Olay | Ne zaman | Unit'teki eşik |
|---|---|---|
| `liveness_low` | `lastProgressBlock()`'tan beri geçen blok sayısı `livenessTimeoutBlocks()`'un `--liveness-low-percent` yüzdesine ulaştı. Close-only'de verilmez. Ad ve yuvarlama gateway'in `LivenessLow` alarmıyla aynıdır (50'de `idle >= timeout / 2`, tamsayı). Gateway'den gelen `liveness_low` ile aynı epizodu paylaşır. | `--liveness-low-percent 50` |
| `l1_close_only` | `closeOnly()` true. Close-only geri dönüşsüz olduğu için olay açık kalır. | yok |
| `challenge_unanswered` | `openChallenges()` içindeki bir inclusion challenge'ı, `challenges(h)` açılış bloğundan beri `--challenge-age-blocks` blok açık. Her challenge'ın açılış bloğu bir kez okunur ve açık kaldıkça hatırlanır (çalıştırma başına en çok 16 yeni okuma). Açılış bloğu okunamayanlar için aşağıya bakın. | `--challenge-age-blocks 900` (2 s blokla ~30 dk) |
| `l1_unreachable` | Art arda `--l1-failures` çalıştırmada L1 okunamadı. Okuma düzelene kadar diğer L1 olayları son okunan hâlini korur. | `--l1-failures 3` (~3 dk) |

**Açılış bloğu okunamayan challenge.** `challenges(h)` okuması başarısız olursa
ya da listeyle çelişen bir yanıt dönerse (aynı blokta kapalı veya head'den sonra
açılmış görünürse), günlüğe tek bir sabit satır yazılır:
`L1 challenge detail read failed`. Çekirdek okuma geçerli kalır, kalan
challenge'lar bir sonraki çalıştırmada okunur. Açılış bloğu bilinmeyen açık bir
challenge olduğu sürece (okuma başarısız oldu, sıraya kaldı ya da challenge
512'lik ilk sayfanın dışında) bunların yaşı, bu durumun ilk görüldüğü head'den
sayılır. Challenge o head'de açık olduğundan gerçek yaşı en az bu kadardır. Bu
yaş `--challenge-age-blocks`'a ulaşınca `challenge_unanswered` verilir; açılış
bloğu okununca saat sıfırlanır. Yaşı bilinmeyen challenge'lar zamanla değişirse
alarm erken gelebilir. Açık kalan ve okunamayan bir challenge ise kaçmaz; alarm
en çok, açılışıyla onu ilk listeleyen çalıştırma arasındaki blok sayısı kadar
gecikir.

**L1 ayarları kaldırılınca veya settlement değişince.** `DARKPERP_L1_RPC` ve
`DARKPERP_SETTLEMENT` boşaltılırsa L1 hiç okunmaz. Bu yüzden yalnız L1
okumalarının verdiği epizodlar (`l1_close_only`, `challenge_unanswered`,
`l1_unreachable`) ve L1 izi durum dosyasında olduğu gibi kalır: ne yeni olay ne
`recovered` gönderilir. Ayarlar aynı kontratla geri gelince aynı epizodlar sürer
ve yalnız gerçekten değişen durum bildirilir. `DARKPERP_SETTLEMENT` başka bir
adrese çevrilirse eski kontratın açık L1 epizodları olaysız kapanır (hiçbiri
toparlanmadı) ve yeni kontratın durumları yeni epizod numarasıyla başlar.
`liveness_low` gateway'in bildirimiyle paylaşıldığı için bu kurala girmez: L1
okumaları kapalıyken yalnız gateway'in `opsAlerts` alanını izler.

Teslim edilemeyen bir izleyici olayı kaydedilmez ve bir sonraki çalıştırmada
yeniden gönderilir. Tek bir çökme ve başarılı yeniden başlatma alarm üretmez.
Bir dakikadan uzun süren kesintiyi `gateway_unreachable` yakalar.

## Doğrulananlar ve kalanlar

- `python3 -m unittest discover -s scripts/ops -p 'test_*.py'` testleri:
  - yedekleme, izleyici ve bildirim davranışı (gerçek loopback HTTP ve rsync dahil),
  - izleyicinin L1 okumaları: eşik kenarları, `PATH`'e konan sahte `cast` ile
    yalnız okuma çağrıları ve RPC URL'sinin argv'ye, durum dosyasına, alarm
    gövdesine ve günlüğe girmemesi. Sahte `cast` de gerçeği gibi hata verirken
    URL'yi stderr'e basar. Günlük denetimi yalnız Python'un `sys.stderr`'ine
    değil, journald'ın okuduğu 1 ve 2 numaralı dosya tanımlayıcılarına da bakar.
    İzleyici bu denetim için ayrı bir süreç olarak da çalıştırılır,
  - açılış bloğu okunamayan challenge'ın geçici (alarm yok) ve kalıcı
    (`challenge_unanswered`) hâli, listeyle çelişen ayrıntı yanıtları, L1
    ayarları kaldırılınca veya settlement değişince L1 epizodları için
    `recovered` gönderilmemesi,
  - unit dosyalarının script'lerle ve argümanlarla tutarlılığı,
  - env şablonlarında değer bulunmaması.
- Unit sözdizimi systemd 255'te `systemd-analyze verify` ile kontrol edildi.
  Tek hata, henüz kurulmamış komut dosyalarıydı.
- Sahte `cast`'in çıktı biçimleri, yerel bir Anvil'deki gerçek
  `DarkPerpSettlement`'a karşı `cast` 1.x ile kontrol edildi. İzleyici gerçek bir
  RPC sağlayıcısına karşı ve systemd sandbox'ı altında `cast` ile **çalıştırılmadı**.
- Bu dosyalarla gerçek bir sunucu kurulumu, başka makinede restore ve gerçek
  ntfy teslimi bu değişiklikte **yapılmadı**. Bunlar ayrı bir tatbikattır
  ([RECOVERY_RESTORE](../docs/RECOVERY_RESTORE.md)).
