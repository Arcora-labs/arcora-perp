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

İlk yeni-checkout build'i (`556e2966…009628`) ve yalnız yol remap edilen build
(`a99995bf…15375b`) ELF pinine eşleşmedi. Sonraki inceleme gömülü kaynak yolu
yanında Cargo'nun kaynak konumuna bağlı crate kimliklerini belirledi. İki workspace
crate'in derleyici metadata değerleri ve yolları normalize edilerek boş target'ta
aynı reviewed ELF byte-byte tekrar üretildi; bu yeni ELF üzerinden CPU setup aynı
program key'i yeniden türetti. [Tarif ve kanıt](reproducible-build/README.md) ilk
hataları da korur. Kaynak/ELF/vkey pinleri değiştirilmedi. Bu, aynı makinede cache'li
bağımlılıkla yerel kaynak → ELF → key bağıdır; bağımsız soğuk ortam ve R02'nin hedef
sürüm/servis bağı hâlâ ayrı kapılardır. Yeni proof üretilmedi.

Yerel Groth16 cache, gerekli circuit/vk/pk dosyaları yerine yalnızca kısmi bir
arşiv içeriyor. Bu dört yeni witness için gerçek proof ve gerçek verifier ile
settlement, üretim servis döngüsü, hedef finalite, tam süreç kesintisi devamı ve
prover yük ölçümü ayrıca tamamlanmalıdır.

[verification.json](verification.json) kaynak/log hash'lerini ve sınırları;
[çalıştırma kılavuzu](../../../FUNDS_LIFECYCLE.md) komutları içerir. Loglardaki ANSI
ve satır sonu boşlukları normalize edildi; ham ve normalize hash'ler ayrı kayıtlı.
