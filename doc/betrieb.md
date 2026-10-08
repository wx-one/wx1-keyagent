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
| OpenBao | hält die Schlüssel und alles, wovon eine Freigabe abhängt |
| Trustee-KBS | gibt den vTPM-State-Schlüssel an den SVSM Ihrer VMs (liest aus OpenBao) |
| PostgreSQL oder CockroachDB | Anfragen, Leases, Protokoll - nichts, wovon eine Freigabe abhängt |

Gehen die Datenbank-Inhalte verloren, gehen der Verlauf und die laufenden Leases verloren,
keine Schlüssel. Geht OpenBao verloren, sind die Disks Ihrer VMs nicht mehr lesbar.
**OpenBao gehört in Ihre Datensicherung.**

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

## Einrichten

### OpenBao

```
bao secrets enable -path=kv -version=1 kv          # Schlüssel, liest auch der KBS
bao secrets enable -path=wx -version=2 kv          # Zustand des wx1-keyagent
bao policy write wx1-keyagent deploy/openbao-policy.hcl
bao token create -policy=wx1-keyagent -period=768h -field=token > /secrets/openbao-token
```

Die Policy erlaubt dem wx1-keyagent nur, was er braucht. Die vTPM-State-Schlüssel kann er
schreiben, aber nicht lesen; die gibt nur der KBS heraus, und nur an den SVSM genau der VM,
zu der sie gehören.

### Geheimnisse

Alle als Dateien, nicht in der Umgebung (die sieht jede Prozessliste):

| Datei (Standard) | Inhalt |
|---|---|
| `/secrets/openbao-token` | Token mit der Policy oben |
| `/secrets/kbs-admin-token` | Admin-Token Ihres KBS (setzt die Ressourcen-Policy) |
| `/secrets/cp-token` | Token, mit dem der Provider Anfragen stellt |
| `/secrets/customer-token` | Ihr Token für die API (Freigaben, Leases, ...) |
| `/secrets/ui-password` | Passwort der UI, Benutzer `kunde` |

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
| `WX_OPENBAO_URL` | `http://127.0.0.1:8200` | |
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
