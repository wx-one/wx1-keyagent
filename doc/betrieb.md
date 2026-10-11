# wx1-keyagent: Betrieb

Der wx1-keyagent läuft bei Ihnen, nicht beim Provider. Er hält die Schlüssel Ihrer
vertraulichen VMs (Confidential VMs, AMD SEV-SNP) und gibt sie nur an eine VM heraus, die
nachweist, dass sie genau die ist, die Sie freigegeben haben. Der Provider stellt Anfragen
("neue VM", "VM auf weiterem Host", ...) und erfährt nur, ob sie umgesetzt oder abgelehnt
wurden. Einen Schlüssel sieht er nie.

## Was dazugehört

| Teil | Wozu |
|---|---|
| wx1-keyagent | dieses Programm: Anfragen prüfen, Freigaben, Schlüsselfreigabe, UI |
| Schlüsselspeicher: OpenBao **oder** ein HSM (PKCS#11) | hält die Disk-Schlüssel und den Schlüssel, mit dem der Zustand signiert ist |
| Trustee-KBS | hält die vTPM-State-Schlüssel und gibt sie an den SVSM Ihrer VMs |
| PostgreSQL oder CockroachDB | der Zustand (Disks, Bindungen, vTPMs, Einstellungen), Anfragen, Leases, Protokoll |

Ein Disk-Schlüssel verlässt den Schlüsselspeicher nie im Klartext, auch nicht zum
wx1-keyagent: Der Speicher verpackt ihn selbst für den Schlüssel, den die attestierte VM für
genau diesen Abruf erzeugt hat (RSA-OAEP eines AES-Schlüssels, damit AES-KWP des
Disk-Schlüssels). Den Zustand in der Datenbank signiert der Schlüsselspeicher (HMAC-SHA256);
ein Eintrag, der außerhalb des Agents geändert oder angelegt wurde, wird nicht verwendet.

Geht der Schlüsselspeicher verloren, sind die Disks Ihrer VMs nicht mehr lesbar. Geht die
Datenbank verloren, sind die Bindungen weg - die Schlüssel ohne Zuordnung, die Disks damit
ebenso. **Schlüsselspeicher, Datenbank und der Speicher Ihres KBS gehören in Ihre
Datensicherung.**

Was die Signatur nicht erkennt: einen ganzen Eintrag, der auf einen älteren Stand
zurückgesetzt wird (etwa aus einer alten Sicherung). Das kann, wer die Datenbank betreibt -
so wie bei OpenBao, wer dessen Storage betreibt. Ein entfernter Eintrag dagegen fällt auf:
Die Schlüsselfreigabe verlangt den Eintrag der Disk und bei persistentem vTPM den der VM.

## Angepasster Trustee-KBS

Ihr KBS muss die angepasste Fassung des Trustee-KBS sein (`wx/kbs:v0.22.0-wx`, Basis
Trustee v0.22.0). Die Anpassung betrifft den SNP-Verifier: Er lehnt Berichte mit einer VMPL
ungleich 0 nicht mehr ab, sondern meldet die VMPL als Claim `vmpl` (dazu `id_key_digest` und
`author_key_digest`).

Nötig ist das, weil Ihre VMs hinter COCONUT-SVSM laufen: Das Gast-Linux hat VMPL2, nur der
SVSM hat VMPL0. Ein unveränderter Trustee-KBS würde jeden Bericht des Gasts ablehnen und
liefert das Claim gar nicht - die Policy, die der wx1-keyagent schreibt, lehnte dann alles ab.

Die Prüfung der VMPL ist damit nicht weg, sie liegt in der Ressourcen-Policy. Die Policy des
wx1-keyagent prüft `snp.vmpl`: Disk-Schlüssel nur an das Gast-Linux (VMPL2),
vTPM-State-Schlüssel nur an den SVSM (VMPL0). **Wer in diesem KBS eine eigene Policy
schreibt, muss `snp.vmpl` ebenso prüfen**, sonst bekäme ein Bericht jeder VMPL jede Ressource.

Die Schlüsselfreigabe für Disks (`wx-release-client` → wx1-keyagent) läuft am KBS vorbei; sie
prüft die Berichte selbst gegen AMDs Zertifikatskette.

Die vTPM-State-Schlüssel legt der wx1-keyagent über die Admin-API des KBS an
(`/kbs/v0/resource/vtpm/<host_data>/state`) und liest sie nie. Wo der KBS sie ablegt, ist
seine Konfiguration (`[[plugins]] name = "resource"`): z. B. in OpenBao (`kv/`, KV v1), in
einem KMS oder auf seiner Platte.

Der Gast braucht einen `wx-release-client`, der den verpackten Schlüssel öffnet (ab den
Images zu wx1-keyagent 0.0.6). Ein älterer Client wird mit *der wx-release-client des Gasts
ist zu alt* abgewiesen.

## Einrichten

### Installieren

Es gibt die Release als Tarball und als Image.

**Tarball** (`wx1-keyagent-<version>-linux-x86_64.tar.gz`): ein einziges Binary
(`sbin/nginx`, nginx mit dem eingebauten wx1-keyagent), ein Startskript, eine systemd-Unit, die OpenBao-Policy, diese Doku, das SBOM
(CycloneDX, `SBOM.cdx.json`) und die Lizenzen der enthaltenen Software
(`THIRD_PARTY_NOTICES`). Alles außer glibc ist statisch gelinkt; vom System braucht er nur
**glibc ab 2.38** (Ubuntu 24.04, Debian 13, RHEL 10, Fedora 39 und neuer). Namen werden wie
bei jedem anderen Programm des Systems aufgelöst (glibc, `/etc/resolv.conf`, NSS).

```
sha256sum -c wx1-keyagent-<version>-linux-x86_64.sha256
tar -xzf wx1-keyagent-<version>-linux-x86_64.tar.gz -C /opt
mv /opt/wx1-keyagent-<version>-linux-x86_64 /opt/wx1-keyagent
useradd --system --home /var/lib/wx1-keyagent wx1-keyagent
cp /opt/wx1-keyagent/wx1-keyagent.service /etc/systemd/system/
# Einstellungen (WX_*) nach /etc/wx1-keyagent.env, Geheimnisse als Dateien
systemctl enable --now wx1-keyagent
```

Ohne systemd: `WX_STATE_DIR=<beschreibbares Verzeichnis> /opt/wx1-keyagent/bin/wx1-keyagent`.
Die CA-Zertifikate sucht das Startskript dort, wo die Distribution sie ablegt; anders
gelegene gibt `SSL_CERT_FILE` an.

**Image** (`ghcr.io/wx-one/wx1-keyagent:<version>`): auf dem gehärteten Debian-13-Image von
container.gov.de (Secure Government Container Initiative) - ohne Shell und Paketmanager,
als Nonroot (65534). Hinzu kommen nur die Release und die glibc-Bibliotheken, die sie
braucht; was genau, steht im Image-SBOM der Release (`.image.cdx.json`). Secrets unter
`/secrets` einhängen, Einstellungen als Umgebung; `/var/lib/wx1-keyagent/kds` ist ein
Volume für AMDs Zertifikate.

### Schlüsselspeicher: OpenBao (Standard)

`WX_KEYSTORE=openbao`. Die Disk-Schlüssel liegen in der Transit-Engine, jeder als eigener
Schlüssel `wx1-disk-<disk>`, exportierbar nur verpackt (`byok-export`).

```
bao secrets enable -path=transit transit
bao policy write wx1-keyagent deploy/openbao-policy.hcl
bao token create -policy=wx1-keyagent -period=768h -field=token > /secrets/openbao-token
```

Die Policy erlaubt dem wx1-keyagent nur, was er braucht, und verbietet ausdrücklich den
Export im Klartext und Backups der Schlüssel. Mit einem anderen Mount als `transit/`
(`WX_OPENBAO_TRANSIT`) ändern sich die Pfade in der Policy mit.

### Schlüsselspeicher: HSM (PKCS#11)

`WX_KEYSTORE=pkcs11`. OpenBao braucht der wx1-keyagent dann nicht. Das PKCS#11-Modul
Ihres HSM bringen Sie mit; der wx1-keyagent lädt es beim Start.

| Variable | |
|---|---|
| `WX_PKCS11_MODULE` | Pfad zum Modul, z. B. `/usr/lib/libCryptoki2_64.so` |
| `WX_PKCS11_TOKEN` | Label des Tokens (der Partition) |
| `WX_PKCS11_PIN_FILE` | Datei mit der PIN des Benutzers (Standard `/secrets/pkcs11-pin`) |
| `WX_PKCS11_ENV` | Umgebungsvariablen, die das Modul selbst liest, z. B. `ChrystokiConfigurationPath` |
| `WX_PKCS11_OAEP` | `sha256` (Standard) oder `sha1` für ein HSM, das RSA-OAEP nur mit SHA-1 kann |

Auf dem Token legt der wx1-keyagent an: `wx1-state` (HMAC-Schlüssel, nie exportierbar) beim
ersten Start und je Disk `wx1-disk-<disk>` (AES-256, sensitiv, nur verpackt exportierbar).
Beim Start prüft er, wie das HSM verpackt (CKM_RSA_AES_KEY_WRAP, sonst RSA-OAEP und
CKM_AES_KEY_WRAP_KWP), indem er einen Testschlüssel verpacken lässt und selbst öffnet; das
Ergebnis steht im Log. Kann das HSM keins davon, startet er nicht.

Im Image steht das Modul nicht; hängen Sie es samt seinen Bibliotheken ein oder bauen Sie
ein Image darauf auf.

Die vTPM-State-Schlüssel liegen auch dann im KBS. Sollen sie ins HSM, braucht der KBS ein
Speicher-Backend dafür; das bringt Trustee v0.22 für das Ressourcen-Plugin nicht mit.

### Aus 0.0.5 und früher übernehmen

Bis 0.0.5 lag der Zustand in OpenBao (`wx/`, KV v2) und die Disk-Schlüssel in `kv/disk/`.
Der erste Start von 0.0.6 übernimmt beides einmal: den Zustand in die Datenbank, jeden
Disk-Schlüssel in die Transit-Engine. Jeder Schlüssel wird geprüft (für einen Testschlüssel
verpackt und wieder geöffnet) und erst dann aus `kv/` gelöscht. `wx/` bleibt, wie es war.
Vorher:

1. `bao secrets enable -path=transit transit`
2. die neue `deploy/openbao-policy.hcl` schreiben (sie erlaubt das Lesen von `wx/` und
   `kv/disk/` für die Übernahme)
3. starten; im Log steht `import done: ...`. Danach die drei Pfade für die Übernahme aus der
   Policy nehmen.

Die VMs brauchen den neuen `wx-release-client` (siehe oben); ihre Passphrasen bleiben
dieselben. `WX_IMPORT_OPENBAO_KV=off` schaltet die Übernahme ab.

### Geheimnisse

Alle als Dateien, nicht in der Umgebung (die sieht jede Prozessliste):

| Datei (Standard) | Inhalt |
|---|---|
| `/secrets/openbao-token` | mit OpenBao: Token mit der Policy oben |
| `/secrets/pkcs11-pin` | mit einem HSM: PIN des Benutzers auf dem Token |
| `/secrets/kbs-admin-token` | Admin-Token Ihres KBS (setzt die Ressourcen-Policy und die vTPM-State-Schlüssel) |
| `/secrets/cp-token` | Token, mit dem der Provider Anfragen stellt |
| `/secrets/customer-token` | Ihr Token für die API (Freigaben, Leases, ...) |
| `/secrets/ui-password` | Passwort der UI, Benutzer `kunde` |

Ohne Schlüsselspeicher - erreichbar, mit Token bzw. PIN, und so verpackend, wie die VMs es
erwarten - startet der Agent nicht (systemd bzw. Docker mit `--restart` versucht es erneut);
der Start sagt, was fehlt. Fehlt eines der anderen Geheimnisse, bleibt nur die zugehörige
Tür zu; der Start sagt einmal, welche.

### TLS

Die API (Anfragen des Providers, Ihre API, die UI) sollte TLS sprechen; der Provider
erreicht sie über ein Netz, das Ihnen nicht allein gehört.

| Variable | |
|---|---|
| `WX_TLS_CERT`, `WX_TLS_KEY` | Zertifikat und Schlüssel der API |
| `WX_CP_CLIENT_CA` | CA, deren Client-Zertifikat der Provider zusätzlich zu seinem Token vorzeigen muss |
| `WX_CP_CLIENT_SUBJECT` | optional: genau dieser Subject, z. B. `/CN=cp.provider.example` |
| `WX_RELEASE_TLS=1` | TLS auch für die Schlüsselfreigabe (Standard: aus, siehe unten) |

Die Schlüsselfreigabe für die VMs bleibt standardmäßig ohne TLS: Der Schlüssel geht
verschlüsselt auf einen Schlüssel, den nur die attestierte VM hat, und jede Antwort ist an
eine frische Nonce gebunden. TLS dort hieße, dass das VM-Image Ihre CA kennen muss.

### Weitere Einstellungen

| Variable | Standard | |
|---|---|---|
| `WX_API_LISTEN` | `127.0.0.1:8095` | API und UI, `adresse:port[,adresse:port]` |
| `WX_RELEASE_LISTEN` | `127.0.0.1:8091` | Schlüsselfreigabe für die VMs - eigener Port |
| `WX_RELEASE_GUEST_URL` | `http://192.168.122.1:8091` | wie die VMs die Freigabe erreichen (steht in ihrer initdata) |
| `WX_DB` | `postgresql://root@127.0.0.1:26257/keyagent?sslmode=disable` | Datenbank |
| `WX_KEYSTORE` | `openbao` | `openbao` oder `pkcs11` |
| `WX_OPENBAO_URL` | `http://127.0.0.1:8200` | |
| `WX_OPENBAO_TRANSIT` | `transit` | Mount der Transit-Engine |
| `WX_KBS_ADMIN_URL` | `http://127.0.0.1:8090` | |
| `WX_REFS` | `/refs/manifest.txt` | Referenzwerte des Providers (`igvm_measurement=...`) |
| `WX_KDS` | `/kds` | Ablage für AMDs Zertifikate (beschreibbar) |
| `WX_LEASE_TTL` | `600` | Sekunden, die eine Lease ohne Verlängerung gilt |
| `WX_WORKERS` | Anzahl Kerne | Worker-Prozesse; jeder hält eine DB-Verbindung |
| `TZ` | UTC | Zeitzone für Zeitfenster |

API und Schlüsselfreigabe laufen auf verschiedenen Ports, und jede Route prüft, auf welchem
eine Anfrage ankam: Ihre VMs erreichen nur die Freigabe, nichts sonst.

Die Tabellen in der Datenbank legt der wx1-keyagent beim Start an.

## Bedienen

Die UI unter `https://<WX_API_LISTEN>/` hat drei Seiten.

### Anfragen

Was der Provider will, mit allem, was geprüft wurde. Fehlgeschlagene Prüfungen lehnen
automatisch ab; Hinweise (⚠) halten nur Auto-Regeln auf. Sie sehen initdata, user-data
(cloud-init) und die SSH-Keys darin. **Wer einen Key in cloud-init hat, kommt nach dem
Entsperren in die VM und an die Daten.**

| Anfrage | wirkt |
|---|---|
| Neue VM mit Systemdisk | sofort (die Disk ist leer); Hinweise trotzdem prüfen, bevor Daten darauf kommen |
| Neues Volume | sofort |
| Volume an VM hängen | nach Freigabe oder Auto-Regel |
| VM auf weiterem Host | nach Freigabe oder Auto-Regel (Host-Pool) |
| Disk von VM getrennt | sofort - nimmt nur Rechte weg |
| Hauptdisk neu installieren | **immer nach Ihrer Freigabe**; der alte Schlüssel und der alte vTPM-State werden vernichtet |
| Disk endgültig löschen | **immer nach Ihrer Freigabe**; der Schlüssel wird vernichtet |
| Neue VM-Instanz will entsperren | nach Freigabe, wenn die Disk das verlangt (siehe Freigabemodus) |

Wird eine VM gelöscht, verliert sie ihre Bindung sofort. Den Schlüssel ihrer Systemdisk
vernichtet erst Ihre Freigabe der automatisch gestellten Löschanfrage - ein Provider, der
VMs löscht, kann so Ihre Sicherungen davon nicht unlesbar machen.

### Disks

- **Freigabemodus** pro Disk: *immer*, *nur im Zeitfenster* (z. B. `Mo-Fr 06:00-22:00`) oder
  *nur nach Bestätigung* jeder neuen VM-Instanz.
- **Replay**: Bei jedem Boot schreibt die VM einen neuen Stand in ihren vTPM; ein
  zurückgespielter (alter) vTPM-State wird daran erkannt. Mit einem Intervall (Sekunden)
  geschieht das auch im laufenden Betrieb.
- **Laufende Instanzen (Lease)**: Pro Disk bekommt nur eine VM-Instanz den Schlüssel. Nach
  einem Absturz läuft die Lease ab (`WX_LEASE_TTL`), oder Sie geben sie hier sofort frei.
- **vTPM der VMs**: Der EK des vTPM wird beim ersten Schlüsselabruf gebunden. Meldet sich die
  VM später mit einem anderen vTPM (State verloren, ausgetauscht oder ein flüchtiger vTPM),
  gibt es keinen Schlüssel, bis Sie die Bindung lösen. Lösen Sie sie nur, wenn Sie wissen,
  warum sich der vTPM geändert hat.
- **Schlüsselabrufe**: das Protokoll, mit dem Grund jeder Ablehnung.

### Regeln & Hosts

- **Auto-Regeln**: Volume an VM und Umzug ohne Ihre Freigabe - nur auf Hosts im Pool und
  nur, wenn cloud-init ausschließlich Benutzer mit bekannten SSH-Keys anlegt (keine Befehle,
  keine Dateien, keine Passwörter).
- **Host-Pool**: Hosts des Providers, denen Sie vertrauen, als `HV-UUID chip_id [Name]`. Die
  chip_id steht von AMD signiert in jedem Bericht; die HV-UUID nennt nur den Host. Passen
  beide nicht zusammen, entscheidet keine Regel, sondern Sie.
- **Bootketten (PCR 4/8/9)**: Bootloader, GRUB-Befehle, Kernel und initrd. Nur freigegebene
  Bootketten bekommen Schlüssel. Ändert sich eine (Kernel-Update in der VM), erscheint sie
  unter *Abgelehnte Bootketten*; geben Sie sie erst frei, wenn Sie wissen, warum sie sich
  geändert hat.

## API

Mit `Authorization: Bearer <customer-token>`:

| | |
|---|---|
| `GET /api/requests/:id` | Status einer Anfrage |
| `POST /api/customer/requests/:id` `{"approve": true\|false}` | entscheiden |
| `POST /api/customer/disks/:id/lease/reset` | Lease sofort freigeben |
| `POST /api/customer/vtpm/:host_data/unbind` | EK-Bindung lösen |
| `POST /api/customer/pcr-refs` `{"4": hex, "8": hex, "9": hex, "label": text}` | Bootkette freigeben |

Der Provider nutzt `POST /api/requests` und `GET /api/requests/:id` mit seinem Token (und
seinem Client-Zertifikat, wenn `WX_CP_CLIENT_CA` gesetzt ist).

## Disks und ihre Namen

- `vm-<uuid>`: die Systemdisk einer VM. Sie gehört zu dieser VM und hängt nie an einer
  anderen.
- `vol-<uuid>`: ein Volume. Es hängt an höchstens einer VM; als Boot-Disk angehängt ist es
  deren Hauptdisk.

Der wx1-keyagent entsperrt die **Hauptdisk** einer VM beim Booten. Weitere Volumes können
Sie in der VM selbst über dieselbe Attestierung entsperren: siehe
[daten-volumes.md](daten-volumes.md).
