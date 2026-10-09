# Clock lifecycle continuation

**Yerel clock fon akışı ve aynı dört witness'ın gerçek SP1 CPU yürütmesi geçti.
R01/R02/R03 yayın kapıları hâlâ açık.**

- [Fon akışı](witnesses/lifecycle.json): gerçek loopback HTTP, Anvil'in kendi
  ayırdığı port, üç normal EOA yatırması, dört imzalı şifreli emir, dört gerçek
  clock anchor kaydı, gerçek ClockBoundVerifier/settlement/vault. İç verifier
  açıkça MockZkVerifier. 50.000 test USDC yatırıldı, 20.000 çekildi, kasada 30.000
  kaldı. Bozuk ve clock'a bağlanmamış proof her pencerede reddedildi.
- İki kullanıcı yayınlanmış Merkle verisini kaydettikten sonra gateway HTTP
  sunucusu ve writer durduruldu; iki task'ın sonlanması beklendi ve dinleyicinin
  kapandığı doğrulandı. İki claim doğrudan kasada tamamlandı. Bu, önceden
  yayınlanmış claim verisi olan yerel kesinti dalıdır; yeni çıkış yayınlamaz.
- [Aynı witness'ların SP1 yürütmesi](guest-replay/manifest.json): 4/4 public
  commitment native sonuçla eşleşti; 97.859.962 toplam guest instruction cycle.
  Kullanılan ELF mevcut bağımsız pinli reviewed artefakttır. Yeni proof üretilmedi.
- [Girdi kontrolleri](guards/verification.json): olumlu native kontrol ve yedi
  negatif geçti: eksik/sırası bozuk pencere, değiştirilmiş commitment/witness,
  ek wire baytı, legacy witness ve symlink dosyası. Altyapı hatası ret sayılmadı.
- Gateway Clippy `--all-targets -- -D warnings` geçti. Akış 10,81 saniye sürdü.

SP1 CPU işlemi başlangıç dahil 32,48 saniye sürdü. macOS `time -l`, maksimum RSS
3.116.449.792 bayt ve ayrı `peak memory footprint` alanında 7.690.918.248 bayt
raporladı. Bunlar bir yürütmenin ölçümüdür; gerçek proof p95 veya hedef ortam
kapasitesi ölçümü değildir. Tam [çıktı](sp1-replay.log) korunur.

Sonraki [Linux CI çalışması](https://github.com/Arcora-labs/arcora-perp/actions/runs/37991243922/job/114025658385)
Anvil 1.8.5'in port duyurusunu stdout'a yazdığını ortaya çıkardı; yerel 1.7.2
stderr kullanıyordu. Harness iki owned pipe'ı da okuyacak şekilde düzeltildi.
Stdout'a yönlendiren yerel shim ile önce hata yeniden üretildi, düzeltmeden sonra
hem doğal stderr akışı (10,86 s) hem zorlanmış stdout akışı (10,63 s) tam fon
testini geçti. ANSI parser regresyonu ve Clippy de geçti. [Düzeltme kanıtı](anvil-stream-fix/verification.json)
bu ek kaynak sürümünü ayrı hash ile kaydeder; yukarıdaki witness/guest kanıtlarının
kaynak hash'leri tarihsel kayıt olarak korunur.

Yeni checkout'ta değişmemiş kaynakla guest yeniden derlendi ancak ELF pinine
eşleşmedi (`556e2966…009628`). Panic string'lerinde checkout'un mutlak yolu
bulunuyor. Eski yola bir kez remap edilerek izole, boş target altında yapılan
ikinci build de eşleşmedi (`a99995bf…15375b`). Bunun tek nedeninin yol olduğu
iddia edilmiyor; yeni vkey üretilmedi, reviewed ELF/vkey pinleri değiştirilmedi.
Bu nedenle tekrar üretilebilir kaynak → ELF → key bağı R02 için açık kalır.

Yerel Groth16 cache, gerekli circuit/vk/pk dosyaları yerine yalnızca kısmi bir
arşiv içeriyor. Bu dört yeni witness için gerçek proof ve gerçek verifier ile
settlement, üretim servis döngüsü, hedef finalite, tam süreç kesintisi devamı ve
prover yük ölçümü ayrıca tamamlanmalıdır.

[verification.json](verification.json) kaynak/log hash'lerini ve sınırları;
[çalıştırma kılavuzu](../../../FUNDS_LIFECYCLE.md) komutları içerir. Loglardaki ANSI
ve satır sonu boşlukları normalize edildi; ham ve normalize hash'ler ayrı kayıtlı.
