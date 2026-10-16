# G5 tatbikatı — başka makinede restore ve gerçek alarm teslimi (16 Ekim 2026)

**PRODUCTION RELEASE HOLD.** Tatbikat gateway'i **demo modunda** çalıştı:
L1 yoktu, yalnız loopback'te dinledi ve dışarıya Caddy route'u açılmadı. Gerçek fon,
L1 işlemi veya proof yoktu. Ops host'unun adresi ve ntfy topic adı bu pakette
bulunmaz.

## Kurulum

- **Binary:** `gateway release binary` workflow'unun #75 merge ref'inden
  ürettiği Linux x86_64 release artifact'ı. Kurulumda SHA-256 doğrulandı.
- **Kaynak kimliği:** Çalışan servisin `GET /identity` yanıtı,
  `source_sha256 c58d07d7…b74a48` (393 dosya) ile artifact'taki
  `service-build-identity.json`'u birebir eşledi. Restore için Mac'te aynı
  kaynaktan derlenen binary de aynı checksum'ı verdi. Bu kimlik
  `self_reported_unattested`'tır; attestation değildir.
- **Unit'ler:** `deploy/` altındaki unit'ler aynen kullanıldı (`darkperp`
  kullanıcısı, sertleştirme, yaklaşık 10 MB RSS). Host'ta 8080 portu dolu
  olduğu için tek değişiklik, gateway ve izleyiciye port 8095 veren bir drop-in
  oldu. Kurulum `install_drill_host.sh` ile yapıldı.
- **Alarm kanalı:** Operatörün mevcut ops ntfy topic'i. Teslimat, ntfy'ın kendi
  mesaj deposundan geri okundu (`alert-deliveries.json`).

## Sonuçlar

| Adım | Sonuç |
|---|---|
| Canlı yedek (`darkperp-backup.service`) | Servis `darkperp` kullanıcısıyla çalıştı. Manifest restore pinlerini taşıyor; demo modda journal yok (`absent`) |
| A. Gateway durdu → dış izleyici | `gateway_unreachable active 1`, durdurmadan **54 s** sonra ntfy'da. Yeniden başlatmadan **42 s** sonra `recovered 1` |
| B. Boot reddi (yanlış restore pin'i) → `OnFailure=` | Gateway her denemede "restore checkpoint SHA-256 mismatch" ile reddetti; **snapshot değişmedi**. Ancak 18 s içinde **4 ayrı** `gateway_service_failed` alarmı gitti |
| B'. Aynısı, `RestartMode=direct` ile | 5 yeniden başlatma, ardından `failed` ve **tam 1 alarm**. Unit dosyası bu PR'da düzeltildi |
| Başka makinede restore (Linux host → macOS) | `restored sealed snapshot`. Karşılaştırılan 8 durum alanının 7'si birebir eşit (aşağıdaki nota bakın). **Ölçülen RTO 9,6 s** |

**RTO ayrıntısı** (`restore-on-second-machine.json`):

| Adım | Süre |
|---|---|
| Aktarım | 3,3 s |
| Anahtar teslimi | 1,3 s |
| Boot ve ilk status | 5,0 s |

RTO'ya dahil olmayanlar: arıza tespiti, makine hazırlığı, binary kurulumu ve
operatörün karar süresi.

**`nextBatchId` notu:** Yedek alınmadan önce kaydedilen değer 349, restore
sonrası ilk okunan değer 352. Demo motoru, boot süresince yaklaşık saniyede
bir batch mühürlüyor. Taze bir genesis açılışı bu alanda 14 gösterir (tatbikat
host'undaki ilk açılış). Yani state yedekten devam etti; fark bu birkaç
saniyelik ilerlemeden geliyor.

**RPO:** Bu tatbikatta 0'dır, ama bu tasarım gereğidir: gateway düzgünce
durduruldu ve son snapshot'ı yazdıktan sonra yedek alındı. Gerçek kayıpta üst
sınır, son yedeğe kadar geçen süredir (timer 30 dk). Canlı host içinde ise
30 s'lik snapshot aralığıdır (`docs/RECOVERY_RESTORE.md`).

## Kapanmayanlar (G5)

- L1 ve pending tx uzlaşması, restore sonrası finalized root sürekliliği:
  L1 modu gerekiyor (GPU prover ve CC kapıları).
- Hedef RTO/RPO değerleri ve kurtarma/alarm sorumluları: operatör kararı.
- Split-brain fencing otomatik değil; restore'dan önce kaynak host'un
  durdurulması operatör adımı olarak kaldı.

## Tatbikat sonrası host durumu

- Gateway durduruldu; backup ve monitor timer'ları kapatıldı.
- Dosyalar, sistem kullanıcıları ve yedekler yerinde bırakıldı.
- Son ntfy olayı `gateway_unreachable active 3`: restore öncesindeki bilerek
  yapılan durdurmadan geldi. Gateway kapalı bırakıldığı için `recovered`
  gelmeyecek.
