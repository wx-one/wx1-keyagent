# Daten-Volumes selbst entsperren

Beim Booten entsperrt die VM nur ihre **Hauptdisk**. Weitere Volumes sind Ihre Sache in der
VM - verschlüsseln, entsperren, einhängen geschieht im Betriebssystem, auf das der Provider
keinen Einfluss hat. Sie können dafür aber dieselbe Attestierung nutzen wie die Hauptdisk:
Der Schlüssel eines Volumes kommt dann nur in genau diese VM-Instanz, auf freigegebenen
Hosts, mit freigegebener Bootkette, und liegt nur bei Ihnen.

## Wie es funktioniert

Hängt der Provider ein Volume an Ihre VM, stellt er eine Anfrage *Volume an VM hängen*. Ist
sie umgesetzt (Ihre Freigabe oder Auto-Regel), ist das Volume an Ihre VM gebunden - an deren
initdata (HOST_DATA) und deren Hosts. Ab dann gibt die Schlüsselfreigabe seinen Schlüssel an
diese VM heraus, mit denselben Prüfungen wie für die Hauptdisk:

- SNP-Bericht von AMD signiert, diese VM-Instanz, freigegebene Plattform
- vTPM der VM über den SVSM, Quote über die Bootkette (PCR 4/8/9)
- Replay-Stand im vTPM, EK-Bindung
- Lease: höchstens eine Instanz hält den Schlüssel
- Freigabemodus des Volumes (immer / Zeitfenster / Bestätigung)

## In der VM

Das Image bringt den Client mit: `/usr/local/sbin/wx-release-client`. Er braucht die URL der
Schlüsselfreigabe, die ID des Volumes und die initdata der VM; beides steht auf der
cidata-ISO.

```sh
# initdata der VM (einmal pro Boot)
m=$(mktemp -d)
mount -o ro /dev/disk/by-label/cidata "$m"
cp "$m/initdata.toml" /run/wx-initdata.toml
umount "$m"; rmdir "$m"
url=$(sed -n 's/^"wx.release.url" *= *"\(.*\)"/\1/p' /run/wx-initdata.toml)

vol=vol-<uuid>                       # ID des Volumes, wie in der UI unter Disks
dev=/dev/vdb                          # das Gerät, siehe unten

# Schlüssel holen und entsperren - der Schlüssel geht nie auf die Platte
wx-release-client "$url" "$vol" /run/wx-initdata.toml | cryptsetup open "$dev" daten --key-file=-
mount /dev/mapper/daten /srv/daten
```

Welches Gerät zu welchem Volume gehört: Die Plattform setzt als Seriennummer die UUID des
Volumes (base64url-kodiert); `lsblk -o NAME,SERIAL` zeigt sie. Den Gerätenamen (`vdb`, ...)
nennt auch die Anfrage *Volume an VM hängen*. Nach dem ersten Formatieren trägt das Volume
seine ID als LUKS-Label, dann geht es eindeutig über `/dev/disk/by-label/<vol-uuid>`.

Beim ersten Mal ist das Volume leer: dann zuerst formatieren, mit demselben Schlüssel:

```sh
wx-release-client "$url" "$vol" /run/wx-initdata.toml | cryptsetup luksFormat "$dev" --key-file=- --label "$vol"
```

### Lease verlängern

Jedes Volume hat seine eigene Lease. Läuft sie ab (`WX_LEASE_TTL`, Standard 10 Minuten),
könnte eine zweite Instanz derselben VM den Schlüssel bekommen. Verlängern Sie sie
regelmäßig, z. B. mit einem systemd-Timer alle 3 Minuten:

```sh
wx-release-client "$url" "$vol" /run/wx-initdata.toml --renew
```

und geben Sie sie beim Herunterfahren zurück:

```sh
wx-release-client "$url" "$vol" /run/wx-initdata.toml --end
```

Die Dienste `wx-release-renew` und `wx-release-end` im Image tun genau das für die
Hauptdisk; für ein Volume legen Sie Kopien mit dessen ID an.

## Gut zu wissen

- Der Schlüssel kommt verschlüsselt auf einen Schlüssel, den der Client für diesen einen
  Abruf erzeugt, und nur der Client kann ihn öffnen. Leiten Sie ihn direkt in `cryptsetup`
  weiter, nicht in eine Datei.
- Der Replay-Stand gehört zur VM, nicht zum Volume: Hauptdisk und Volumes zählen denselben
  Stand im vTPM weiter. Das ist gewollt.
- Abgelehnte Abrufe stehen mit Grund in der UI unter *Disks → Schlüsselabrufe*.
- Ein Volume, das an keiner VM hängt, bekommt nie einen Schlüssel.
- Wird ein Volume abgehängt, gilt die Bindung sofort nicht mehr; ein bereits entsperrtes
  Volume bleibt in der laufenden VM offen, bis Sie es schließen.
