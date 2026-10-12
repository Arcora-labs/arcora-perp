# Bağımsız legacy curl request admission incelemesi

Başlangıç main: `c56a6114fbc2a43be8e3b414fef00be91f5efa5f`. Yalnız public kaynak okundu; curl, servis, endpoint, Cargo veya proof çalıştırılmadı.

Üç curl argv yolunda `--globoff` ve HTTP(S) protokol allowlist yoktur. `-q` ve `--`, curl URL expansion ve protokol seçimini sınırlamaz. Endpoint operatör config'inden gelir; public HTTP isteği veya peer yanıtı seçmez. Bu nedenle uzaktan critical SSRF veya attestation bypass iddiası desteklenmiyor.

Üç çağrıya `--globoff` ve `--proto =http,https` eklemek uygun dar pakettir. Base/suffix, schemeless HTTP, proxy ortamı, no-follow GET ve typed 401 tek re-handshake davranışı korunmalıdır. Native fixture/typecheck sonucu gelmeden fix veya davranış PASS iddiası yoktur.

Kalan kapsam adayları:

- Query/fragment bulunan base'e servis yolu metin olarak eklenir; suffix request path'ine girmeyebilir. Parser/route kontratı seçilen paket dışındadır.
- Outbound POST body byte cap'i yoktur. Receiver 512 MiB üst sınırı uygular. Birikmiş op/full-state witness, inbound tek HTTP isteği 2 MiB varsayılan/8 MiB maksimumla aynı değildir. Kaynak tek başına remote OOM kanıtı değildir; post-serialization cap daha önceki allocation'ı da sınırlamış sayılmaz.
- Bearer argv'dedir; process command line görebilen local observer koşuluyla gizlilik değerlendirmesi gerekir. Peer token göndermiyor: token yerelde 66 karakter hex veya dev sabitidir. Uzaktan CRLF injection gösterilmedi.

Response bounds, hata redaksiyonu, child kill/reap, proof/measurement/replay gates ve root pins korunmalı. Production HOLD devam eder. Kaynak hashleri/kabul matrisi: `independent-audit-initial.json`.
