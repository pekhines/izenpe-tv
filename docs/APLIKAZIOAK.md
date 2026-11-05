# Aplikazioen gida: Firefox, AutoFirma, Idazki Desktop…

`./install.sh`-ek urrats hauek automatikoki egiten ditu, aplikazioak aurkitzen baditu.
Hemen azaltzen da zer egiten duen, nola egin eskuz, eta nola **erabili** aplikazio
bakoitza ziurtagiriarekin.

Bide guztietan, modulua hemen dago:

```
~/.local/lib/izenpe-tv/libizenpe-pkcs11.so
```

**Beti, erabili aurretik:** `izenpelogin` exekutatu eta saioa hasi (NAN/AIZ + pasahitza +
SMS). Saiorik gabe "Izenpe TV" tokena hutsik agertzen da: ez dago ziurtagiririk.

**PINa:** tokenak ez du PINik behar (autentifikazioa `izenpelogin`-en egiten da). Aplikazio
batek PINa edo "pasahitz nagusia" eskatzen badu, idatzi edozer.

Edukia:
- [Firefox (eta Thunderbird)](#firefox-eta-thunderbird)
- [AutoFirma](#autofirma)
- [Idazki Desktop](#idazki-desktop)
- [Chrome / Chromium, LibreOffice](#chrome--chromium-libreoffice)
- [Egiaztapenak](#egiaztapenak)

---

## Firefox (eta Thunderbird)

### Konfigurazioa (behin bakarrik)

**Firefox natiboa (deb/rpm/tar):** modulua profilean kargatu.

- Interfazetik: *Ezarpenak → Pribatutasuna eta segurtasuna → Ziurtagiriak →
  Segurtasun-gailuak → Kargatu*
  - Moduluaren izena: `Izenpe Tarjeta Virtual`
  - Moduluaren fitxategia: `/home/<zu>/.local/lib/izenpe-tv/libizenpe-pkcs11.so`
- Edo terminaletik (Firefox itxita):
  ```bash
  modutil -dbdir sql:$HOME/.mozilla/firefox/<profila> -add "Izenpe Tarjeta Virtual" \
          -libfile ~/.local/lib/izenpe-tv/libizenpe-pkcs11.so
  ```

**Firefox flatpak (`org.mozilla.firefox`):** gainera, sandbox-ak modulua eta agentearen
socketa ikusi behar ditu:

```bash
flatpak override --user --filesystem=~/.local/lib/izenpe-tv:ro \
                        --filesystem=xdg-run/izenpe-tv org.mozilla.firefox
```

Ondoren, itxi Firefox **guztiz** eta ireki berriro, eta kargatu modulua interfazetik
(goian bezala).

Thunderbird-en berdin (*Ezarpenak → Pribatutasuna eta segurtasuna → Segurtasun-gailuak*),
eta flatpak bada `org.mozilla.thunderbird`-ekin.

### Nola sartu webgune batean ziurtagiriarekin

1. `izenpelogin` → saioa hasi.
2. Firefoxen, joan webgunera (Izenpe, Eusko Jaurlaritzaren egoitza elektronikoa,
   Gizarte Segurantza, Ogasuna…), eta aukeratu **"ziurtagiri digitalarekin sartu"**.
3. Firefoxek *Identifikazio-eskaera* leihoa erakutsiko du: aukeratu zure ziurtagiria
   (`IZEN ABIZENAK - NAN`, Izenpek jaulkia) eta sakatu *Ados*.
   "Gogoratu erabaki hau" markatu dezakezu.
4. "Izenpe TV" tokenaren pasahitza eskatzen badu, idatzi edozer.

Firefox ireki ondoren saioa hasi baduzu, eta ziurtagiria ez bada agertzen, berrabiarazi
Firefox (tokena abiaraztean irakurtzen du).

---

## AutoFirma

### Konfigurazioa (behin bakarrik)

AutoFirmak (1.9) Firefoxen ziurtagiri-biltegia erabiltzen du:

- **Firefox natiboa** baduzu (`~/.mozilla/firefox/profiles.ini` existitzen da), Firefoxen
  profilean kargatutako modulua erabiltzen du: aurreko atala nahikoa da.
- **Firefox flatpak** baduzu, AutoFirmak ez du profila aurkitzen, eta NSS datu-base
  partekatua erabiltzen du: **`~/.pki/nssdb`** (Chromek ere hori erabiltzen du). Erregistratu
  modulua hor:
  ```bash
  cp -a ~/.pki/nssdb ~/.pki/nssdb.bak-$(date +%F)       # babeskopia
  modutil -dbdir sql:$HOME/.pki/nssdb -add "Izenpe Tarjeta Virtual" \
          -libfile ~/.local/lib/izenpe-tv/libizenpe-pkcs11.so -force
  ```
  (`modutil` ez baduzu eta flatpak SDK bat baduzu:
  `flatpak run --filesystem=~/.pki/nssdb --filesystem=~/.local/lib/izenpe-tv:ro --command=modutil org.freedesktop.Sdk//25.08 …`)

**AutoFirma flatpak (`es.gob.afirma`):** sandbox-ari baimenak eman:

```bash
flatpak override --user --filesystem=~/.local/lib/izenpe-tv:ro \
                        --filesystem=xdg-run/izenpe-tv es.gob.afirma
```

### Nola sinatu

**Fitxategi bat sinatzea (AutoFirma bera):**
1. `izenpelogin` → saioa hasi.
2. Ireki AutoFirma → *Hautatu sinatzeko fitxategia* → aukeratu PDFa (edo beste edozer).
3. Sakatu *Sinatu*. Ziurtagiri-hautatzailean aukeratu zure Izenpeko ziurtagiria.
4. PINa eskatzen badu, edozer. Gorde sinatutako fitxategia (`*_signed.pdf`…).

**Webgune batetik (egoitza elektronikoak):** webguneak AutoFirma abiarazten du (`afirma://`).
Zuk ziurtagiria aukeratu besterik ez duzu egin behar, goian bezala.

---

## Idazki Desktop

Idazki Desktop Izenperen sinadura-aplikazioa da. Euskal administrazioaren webguneek
(adib. `eidas.izenpe.com`-eko sinadura-orriek) abiarazten dute.

### Instalazioa eta konfigurazioa

1. Deskargatu Izenperen webgunetik Linuxerako bertsioa (`idazki-desktop-linux64.run`) eta
   instalatu: `/usr/local/idazki-desktop`-en instalatzen da.
2. Idazkik `/usr/local/idazki-desktop/pkcs11.properties` fitxategiko liburutegi guztiak
   probatzen ditu (lerro bakoitzean bide bat). Gehitu gurea (sudo behar du):
   ```bash
   printf '\n%s\n' "$HOME/.local/lib/izenpe-tv/libizenpe-pkcs11.so" | \
       sudo tee -a /usr/local/idazki-desktop/pkcs11.properties
   ```
   `./install.sh`-ek hau egiten du Idazki aurkitzen badu (galdetu egiten du).

> ⚠️ Fitxategi horrek **ez du lerro-jauzirik amaieran**. `echo … >>` erabiliz gero, bidea
> aurreko lerroari itsasten zaio (`…/opensc-pkcs11.so/home/…`), eta Idazkik PKCS12
> fitxategi bat eskatzen du. Horregatik `printf '\n%s\n'`.

> ⚠️ **Idazki eguneratzean** fitxategia gainidatz daiteke. Eguneratu ondoren, exekutatu
> berriro `./install.sh` edo egiaztatu: `grep izenpe-tv /usr/local/idazki-desktop/pkcs11.properties`

### Nola sinatu

1. `izenpelogin` → saioa hasi.
2. Webgunean sakatu *Sinatu* (edo *Idazkirekin sinatu*). Nabigatzaileak Idazki Desktop
   irekitzeko baimena eskatuko dizu.
3. Idazkik PINa eskatzen badu, idatzi edozer.
4. Idazkik ziurtagiria hartzen du eta sinatzen du. Leihoa bakarrik ixten da amaitzean.

### Arazoak

Idazkiren loga: **`~/.idazki-desktop-trace.txt`**.

| Logean | Esanahia |
|---|---|
| `La ruta …opensc-pkcs11.so/home/… no existe` | Bidea itsatsita: konpondu `sudo sed -i 's|\.so/home|.so\n/home|' /usr/local/idazki-desktop/pkcs11.properties` |
| `Usando PKCS12...` | Ez du PKCS#11 modulurik kargatu (goikoa, edo lerroa falta da). |
| `Certificates size: 0` | Saioa iraungita: `izenpelogin`. |
| `CKR_FUNCTION_FAILED` sinatzean | Agentearen loga begiratu: `journalctl --user -u izenpe-tv-agent`. Bertsio zaharra bada, `git pull && ./install.sh`. |

---

## Chrome / Chromium, LibreOffice

- **Chrome/Chromium** (natiboa): `~/.pki/nssdb` erabiltzen du (ikus AutoFirma atala).
  Webgune batean ziurtagiria eskatzen denean, hautatzailea agertuko da.
- **LibreOffice** (*Fitxategia → Sinadura digitalak*): Firefoxen profila edo `~/.pki/nssdb`
  erabiltzen du (*Tresnak → Aukerak → Segurtasuna → Ziurtagiria*-n aukeratu daiteke).
- **p11-kit** darabilten aplikazioak (GnuTLS, OpenSSL `pkcs11-provider`…): `install.sh`-ek
  `~/.config/pkcs11/modules/izenpe-tv.module` sortzen du.

---

## Egiaztapenak

```bash
# saioa aktibo dago?
izenpe-tv whoami

# agentea martxan?
systemctl --user status izenpe-tv-agent

# moduluak ziurtagiria erakusten du? (opensc paketea)
pkcs11-tool --module ~/.local/lib/izenpe-tv/libizenpe-pkcs11.so -O

# NSS datu-base partekatuan (AutoFirma/Chrome)?
certutil -L -d sql:$HOME/.pki/nssdb -h "Izenpe TV"
```

Azken komandoak zure ziurtagiria `u,u,u` markarekin erakutsi behar du.
