# izenpe-tv — Izenperen Txartel Birtuala Linuxen

Izenperen **hodeiko ziurtagiri profesionala** (Txartel Birtuala / Tarjeta Virtual) Linuxen
erabiltzeko bezero **ez-ofiziala**. Izenpek Windows, macOS eta mugikorretarako bezeroak
bakarrik eskaintzen ditu. Honekin, ziurtagiria txartel adimendun bat balitz bezala
agertzen da Firefox, Chrome, AutoFirma, Idazki Desktop, LibreOffice eta Thunderbird-en.

Gako pribatua ez da inoiz Izenperen HSMtik ateratzen: saioa hasten duzu (NAN/AIZ +
pasahitza + SMS kodea) eta sinadura bakoitza urrunean egiten da. Protokoloa Windowseko
aplikazio ofizialetik atera da **elkarreragingarritasunerako** (2009/24/EE Zuzentaraua,
6. art.), eta norberaren ziurtagiria erabiltzeko bakarrik balio du.

> ⚠️ Ez dago Izenperekin lotuta, eta Izenpek ez du onartzen. Zure ardurapean erabili.
> Arazoak badituzu, ez jo Izenperen laguntza-zerbitzura: ireki *issue* bat hemen.

## Nola dabilen

```
aplikazioa ──PKCS#11──► libizenpe-pkcs11.so ──socket──► izenpe-tv-agent ──HTTPS──► Izenpe HSM
                                                              ▲
                                       izenpelogin (NAN + pasahitza + SMS)
```

1. **`izenpelogin`**: Izenperen saio-hasierako leihoa irekitzen du eta saioa gordetzen du.
2. **`libizenpe-pkcs11.so`**: aplikazioek kargatzen duten PKCS#11 modulua (txartel-irakurgailu
   baten "driverra" balitz bezala).
3. **`izenpe-tv-agent`**: atzeko planoko prozesua (systemd erabiltzaile-unitatea). Saioa
   gordetzen du eta sinadurak Izenperi eskatzen dizkio. `izenpelogin`-ek abiarazten du.

## Instalazioa

Behar dena: Linux x86_64, Python ≥ 3.10 (`venv`-arekin), C konpilatzailea eta `make`,
eta, aukeran, `modutil` (NSS) eta `7z` edo `msiextract`.

```bash
# Debian / Ubuntu
sudo apt install git python3-venv build-essential libnss3-tools 7zip
# Fedora
sudo dnf install git python3 gcc make nss-tools 7zip
# Arch
sudo pacman -S git python base-devel nss 7zip
```

1. **Klonatu** repo-a:
   ```bash
   git clone https://github.com/pekhines/izenpe-tv.git
   cd izenpe-tv
   ```
2. **Deskargatu Izenperen instalatzaile ofiziala Windowserako**
   (`TarjetaVirtual-Setup-X.Y.Z.msi`) Izenperen webgunetik, eta utzi `~/Deskargak`-en
   (edo `~/Downloads`-en). Ez da instalatzen: aplikazio ofizialak bere barruan dituen OAuth
   kredentzialak ateratzeko bakarrik behar da. Proiektu honek ez ditu kredentzial horiek
   banatzen.
3. **Exekutatu instalatzailea** (ez du root behar):
   ```bash
   ./install.sh
   # edo instalatzailea beste nonbait badago:
   ./install.sh --msi /bidea/TarjetaVirtual-Setup-X.Y.Z.msi
   ```
   Modulua konpilatu, Python ingurunea sortu, `izenpelogin` menuan jarri, kredentzialak
   atera eta modulua aurkitzen dituen aplikazioetan erregistratzen du (galdetu egiten du
   aurretik).

Eguneratzeko: `git pull && ./install.sh`. Desinstalatzeko: `./install.sh --uninstall`.

## Erabilera

1. Ireki **izenpelogin** menutik (edo `izenpelogin` terminalean).
2. Sartu NAN/AIZ, pasahitza eta SMS bidez jasotako kodea.
3. Jakinarazpen batek esango dizu saioa noiz arte dagoen aktibo. Iraungi baino 5 minutu
   lehenago gogorarazi egingo dizu.
4. Erabili ziurtagiria aplikazioetan. PINik ez da behar: eskatzen badute, idatzi edozer.

Aplikazio bakoitzaren gida zehatza: **[docs/APLIKAZIOAK.md](docs/APLIKAZIOAK.md)**
— Firefox (webguneetan sartzea), AutoFirma, Idazki Desktop, Chrome, LibreOffice.

Saioa iraungitzen denean, berriro `izenpelogin` besterik ez. Konfigurazioa behin bakarrik
egiten da.

### Terminaletik

```bash
izenpe-tv whoami                  # zure datuak (izena, CIF…)
izenpe-tv identities              # sinadura-identitateak
izenpe-tv cert <id> --pem         # ziurtagiria
echo -n "kaixo" | izenpe-tv sign <id> --hash sha256
```

## Arazoak

| Arazoa | Konponbidea |
|---|---|
| Ziurtagiria ez da agertzen | Saioa iraungita? Exekutatu `izenpelogin`. Aplikazioa berrabiarazi. |
| `HTTP 401` | Saioa iraungi da: `izenpelogin`. |
| Flatpak Firefox/AutoFirmak ez du modulua ikusten | `./install.sh` berriro, eta aplikazioa guztiz itxi eta ireki. |
| Idazkik PKCS12 fitxategia eskatzen du | Ikus [docs/APLIKAZIOAK.md](docs/APLIKAZIOAK.md#idazki-desktop). |
| Agentearen loga | `journalctl --user -u izenpe-tv-agent` |
| izenpelogin-en loga | `~/.cache/izenpe-tv/izenpelogin.log` |

## Egitura

```
install.sh              erabiltzaile-instalatzailea
pkcs11/                 PKCS#11 modulua (C, libc bakarrik)
src/izenpe_tv/
  launcher.py           izenpelogin
  agent.py              agentea (PKCS#11 ↔ Izenpe)
  webview_login.py      saio-hasierako leihoa (Qt WebEngine)
  credentials.py        OAuth kredentzialak instalatzaile ofizialetik atera
  oauth.py, api.py      OAuth eta Izenperen REST APIa
docs/APLIKAZIOAK.md     aplikazio bakoitzaren gida
docs/PROTOCOL.md        protokoloaren deskribapen teknikoa
```

## Lizentzia

[GPL-3.0](LICENSE). `pkcs11/include/pkcs11.h` p11-kit-etik dator (bere lizentziarekin).
