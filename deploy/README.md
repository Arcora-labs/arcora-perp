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
| `systemd/darkperp-monitor.{service,timer}` | Dakikada bir public sağlık okuması yapar ([gateway_monitor.py](../scripts/ops/gateway_monitor.py)). |
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
| Gateway içi (`ops_alerts.rs`, şema `arcora.ops-alert.v1`) | `settlement_held`, `persistence_failed`, `deposit_halted`, `archive_pressure`, `bond_shortfall`, `unanswerable_challenge`, `challenge_discovery_failed`, `stale_anchor`, `liveness_low` | Süreç ayaktayken başlangıçta ve toparlanmada birer kez |
| Dış izleyici (şema `arcora.ops-monitor.v1`) | `gateway_unreachable`, `settlement_held`, `deposit_halted`, `settle_stall`; gateway ayaktayken `/api/state` `opsAlerts` içindeki `bond_shortfall`, `unanswerable_challenge`, `challenge_discovery_failed`, `stale_anchor`, `liveness_low` | Süreç düşük veya kilitliyken de çalışır |
| `OnFailure=` (`arcora.ops-monitor.v1`) | `gateway_service_failed`, `backup_failed`, `monitor_failed` | Unit failed durumuna geçtiğinde |

`settle_stall`: Mühürlenmiş bir pencere bekliyor (`openWindowId > l1.batchCount`)
ve aynı gecikme `--stall-seconds` (900 s) boyunca sürüyor. L1 yoksa bu kontrol
yapılmaz. Eşik yalnız fixture'larla sınandı; canlı L1 gateway'inde ayrıca
doğrulanmalıdır.

Teslim edilemeyen bir izleyici olayı kaydedilmez ve bir sonraki çalıştırmada
yeniden gönderilir. Tek bir çökme ve başarılı yeniden başlatma alarm üretmez.
Bir dakikadan uzun süren kesintiyi `gateway_unreachable` yakalar.

## Doğrulananlar ve kalanlar

- `python3 -m unittest discover -s scripts/ops -p 'test_*.py'` testleri:
  - yedekleme, izleyici ve bildirim davranışı (gerçek loopback HTTP ve rsync dahil),
  - unit dosyalarının script'lerle ve argümanlarla tutarlılığı,
  - env şablonlarında değer bulunmaması.
- Unit sözdizimi systemd 255'te `systemd-analyze verify` ile kontrol edildi.
  Tek hata, henüz kurulmamış komut dosyalarıydı.
- Bu dosyalarla gerçek bir sunucu kurulumu, başka makinede restore ve gerçek
  ntfy teslimi bu değişiklikte **yapılmadı**. Bunlar ayrı bir tatbikattır
  ([RECOVERY_RESTORE](../docs/RECOVERY_RESTORE.md)).
