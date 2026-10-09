/**
 * The agent's own words, in German, for the UI.
 *
 * Checks, reasons and the key release log are written in English: the
 * provider reads them through the API, and they stay as they are in the
 * database. The customer reads them in the UI, in German. A text this
 * table does not know is shown as it is - a new message is never hidden,
 * only not yet translated.
 */
#ifndef WX_DE_H
#define WX_DE_H

#include "util.h"

#include <ctype.h>
#include <string.h>

/* word for word */
static const char *const deExact[][2] = {
    /* request checks */
    {"VM UUID valid", "VM-UUID gültig"},
    {"initdata names this VM UUID", "initdata nennt diese VM-UUID"},
    {"initdata names our key release", "initdata nennt diese Schlüsselfreigabe"},
    {"initdata names the hashes of user-data and meta-data",
     "initdata enthält die Hashes von user-data und meta-data"},
    {"chip_id valid", "Chip-ID gültig"},
    {"state readable (OpenBao)", "Zustand lesbar (OpenBao)"},
    {"chip_id does NOT match the HV UUID in the host pool (hardware swapped?)",
     "Chip-ID passt NICHT zur HV-UUID im Host-Pool (Hardware getauscht?)"},
    {"disk ID valid (vm-<uuid> or vol-<uuid>)", "Disk-ID gültig (vm-<uuid> oder vol-<uuid>)"},
    {"no disk ID of its own (a system disk is named by its VM)",
     "keine eigene Disk-ID (eine Systemdisk heißt nach ihrer VM)"},
    {"the VM has no system disk yet", "die VM hat noch keine Systemdisk"},
    {"a volume is named vol-<uuid>", "ein Volume heißt vol-<uuid>"},
    {"volume ID not taken yet", "Volume-ID noch frei"},
    {"disk exists", "Disk existiert"},
    {"not a system disk (that belongs to its VM)", "keine Systemdisk (die gehört zu ihrer VM)"},
    {"disk attached to no other VM", "Disk hängt an keiner anderen VM"},
    {"the VM has no system disk (it boots from this volume)",
     "die VM hat keine Systemdisk (sie bootet von diesem Volume)"},
    {"initdata is the VM's own (as bound to its system disk)",
     "initdata ist die der VM (so an ihre Systemdisk gebunden)"},
    {"the VM has no system disk here; bound to the initdata as sent",
     "die VM hat hier keine Systemdisk; gebunden an die initdata, wie sie kam"},
    {"disk is attached to a VM", "Disk hängt an einer VM"},
    {"request names this VM", "Anfrage nennt diese VM"},
    {"disk is attached to this VM", "Disk hängt an dieser VM"},
    {"it is the VM's main disk", "es ist die Hauptdisk der VM"},
    {"approving shreds the disk's key and the VM's vTPM state: the data on it is gone for good",
     "Freigeben vernichtet den Schlüssel der Disk und den vTPM-Zustand der VM: "
     "die Daten darauf sind endgültig verloren"},
    {"disk attached to no VM", "Disk hängt an keiner VM"},
    {"unknown request type", "unbekannte Art von Anfrage"},
    {"the VM was deleted; approving shreds the key of its system disk for good",
     "die VM wurde gelöscht; Freigeben vernichtet den Schlüssel ihrer Systemdisk endgültig"},
    {"initdata cannot be read", "initdata nicht lesbar"},

    /* cloud-init */
    {"user-data is not #cloud-config (a script, for one)",
     "user-data ist kein #cloud-config (etwa ein Skript)"},
    {"cannot read user-data", "user-data nicht lesbar"},
    {"user-data holds more than one document", "user-data enthält mehr als ein Dokument"},
    {"user-data cannot be read after the first document",
     "user-data ist nach dem ersten Dokument nicht lesbar"},
    {"user-data is not a mapping", "user-data ist keine Zuordnung (mapping)"},
    {"allows SSH with a password", "erlaubt SSH mit Passwort"},
    {"users is not a list", "users ist keine Liste"},
    {"no known SSH keys set", "keine bekannten SSH-Keys hinterlegt"},

    /* deciding */
    {"denied by the customer", "vom Kunden abgelehnt"},
    {"disk ID is taken", "Disk-ID ist schon vergeben"},
    {"disk is already attached to a VM", "Disk hängt schon an einer VM"},
    {"disk is being deleted", "Disk wird gerade gelöscht"},
    {"cannot write the binding (OpenBao)", "Bindung nicht schreibbar (OpenBao)"},
    {"cannot write the vTPM state key (OpenBao)", "vTPM-Zustandsschlüssel nicht schreibbar (OpenBao)"},
    {"cannot write the vTPM entry (OpenBao)", "vTPM-Eintrag nicht schreibbar (OpenBao)"},
    {"cannot overwrite the disk key (OpenBao)", "Disk-Schlüssel nicht überschreibbar (OpenBao)"},
    {"cannot shred the old vTPM state (OpenBao)", "alter vTPM-Zustand nicht vernichtbar (OpenBao)"},
    {"cannot remove the old binding (OpenBao)", "alte Bindung nicht entfernbar (OpenBao)"},
    {"cannot mark the disk (OpenBao)", "Disk nicht markierbar (OpenBao)"},
    {"cannot shred a vTPM state key (OpenBao)", "vTPM-Zustandsschlüssel nicht vernichtbar (OpenBao)"},
    {"cannot list the vTPMs (OpenBao)", "vTPMs nicht auflistbar (OpenBao)"},
    {"cannot write the disk (OpenBao)", "Disk nicht schreibbar (OpenBao)"},
    {"cannot write the disk key (OpenBao)", "Disk-Schlüssel nicht schreibbar (OpenBao)"},
    {"cannot mark the disk active (OpenBao)", "Disk nicht aktivierbar (OpenBao)"},
    {"cannot remove the binding (OpenBao)", "Bindung nicht entfernbar (OpenBao)"},

    /* the key release */
    {"key delivered", "Schlüssel ausgeliefert"},
    {"lease given back", "Lease zurückgegeben"},
    {"lease renewed", "Lease verlängert"},
    {"request is not a JSON object", "Anfrage ist kein JSON-Objekt"},
    {"no memory", "kein Speicher"},
    {"disk_id missing or not vm-<uuid> / vol-<uuid>", "disk_id fehlt oder ist nicht vm-<uuid> / vol-<uuid>"},
    {"no randomness", "kein Zufall verfügbar"},
    {"database not reachable", "Datenbank nicht erreichbar"},
    {"session unknown, used or expired", "Sitzung unbekannt, verbraucht oder abgelaufen"},
    {"session unknown, used or expired (first /v1/attest)",
     "Sitzung unbekannt, verbraucht oder abgelaufen (erst /v1/attest)"},
    {"session used or expired", "Sitzung verbraucht oder abgelaufen"},
    {"request incomplete", "Anfrage unvollständig"},
    {"guest report not from the guest (VMPL)", "Gast-Report stammt nicht vom Gast (VMPL)"},
    {"guest report not bound to the nonce and the guest key",
     "Gast-Report nicht an Nonce und Gast-Schlüssel gebunden"},
    {"initdata does not match HOST_DATA", "initdata passt nicht zu HOST_DATA"},
    {"state not readable (OpenBao)", "Zustand nicht lesbar (OpenBao)"},
    {"disk attached to no VM (no binding)", "Disk hängt an keiner VM (keine Bindung)"},
    {"VM configuration (HOST_DATA) not approved for this disk",
     "VM-Konfiguration (HOST_DATA) für diese Disk nicht freigegeben"},
    {"host not approved for this disk", "Host für diese Disk nicht freigegeben"},
    {"vTPM report not from the SVSM (VMPL0)", "vTPM-Report stammt nicht vom SVSM (VMPL0)"},
    {"vTPM report not bound to the nonce and the EK", "vTPM-Report nicht an Nonce und EK gebunden"},
    {"vTPM report belongs to another VM", "vTPM-Report gehört zu einer anderen VM"},
    {"EK cannot be read", "EK nicht lesbar"},
    {"AK cannot be read", "AK nicht lesbar"},
    {"the vTPM is not the same any more (EK): state lost, swapped or ephemeral. No release "
     "until the customer unbinds the EK",
     "der vTPM ist nicht mehr derselbe (EK): Zustand verloren, getauscht oder flüchtig. "
     "Keine Freigabe, bis die EK-Bindung gelöst wird"},
    {"credential not opened (another vTPM)", "Credential nicht geöffnet (anderer vTPM)"},
    {"AK lost", "AK verloren"},
    {"boot chain (PCR 4/8/9) not in the approved reference values",
     "Bootkette (PCR 4/8/9) nicht unter den freigegebenen Referenzwerten"},
    {"disk no longer bound to this VM and host", "Disk nicht mehr an diese VM und diesen Host gebunden"},
    {"disk is already unlocked in another running instance (lease)",
     "Disk ist schon in einer anderen laufenden Instanz entsperrt (Lease)"},
    {"renewal without a valid lease", "Verlängerung ohne gültige Lease"},
    {"replay stand missing (replay protection)", "Replay-Stand fehlt (Replay-Schutz)"},
    {"cannot confirm the replay stand (OpenBao)", "Replay-Stand nicht bestätigbar (OpenBao)"},
    {"disk key not readable (OpenBao)", "Disk-Schlüssel nicht lesbar (OpenBao)"},
    {"guest key unusable (want RSA 3072 or more)", "Gast-Schlüssel unbrauchbar (RSA ab 3072 Bit nötig)"},
    {"the disk asks for confirmation", "die Disk verlangt eine Bestätigung"},
    {"no VCEK for this chip (AMD KDS) or the chain does not check out",
     "kein VCEK für diesen Chip (AMD KDS) oder die Kette stimmt nicht"},
    {"SNP report has the wrong size", "SNP-Report hat die falsche Größe"},
    {"SNP report signed with an unknown algorithm", "SNP-Report mit unbekanntem Verfahren signiert"},
    {"SNP report signature invalid", "Signatur des SNP-Reports ungültig"},
    {"SVSM/firmware measurement not in the reference values",
     "SVSM/Firmware-Measurement nicht unter den Referenzwerten"},
    {"debug allowed", "Debugging erlaubt"},
    {"migration agent allowed", "Migrations-Agent erlaubt"},
    {"quote not signed by the AK", "Quote nicht vom AK signiert"},
    {"quote is not a TPM quote over this session's nonce", "Quote ist kein TPM-Quote über die Nonce dieser Sitzung"},
    {"quote is not over the SHA-256 bank alone", "Quote nicht allein über die SHA-256-Bank"},
    {"quote cannot be read", "Quote nicht lesbar"},
    {"PCR file is not for the quoted selection", "PCR-Datei passt nicht zur Auswahl im Quote"},
    {"PCR values do not match the quote", "PCR-Werte passen nicht zum Quote"},
    {"replay stand not signed by the AK of this vTPM", "Replay-Stand nicht vom AK dieses vTPM signiert"},
    {"replay stand is not an NV certification over this session's nonce",
     "Replay-Stand ist keine NV-Zertifizierung über die Nonce dieser Sitzung"},
    {"replay stand incomplete", "Replay-Stand unvollständig"},
    {"replay stand out of range", "Replay-Stand außerhalb des gültigen Bereichs"},
    {"EK is not an RSA key", "EK ist kein RSA-Schlüssel"},
    {"EK template not supported (want SHA-256, AES-CFB)", "EK-Vorlage nicht unterstützt (SHA-256, AES-CFB nötig)"},
    {"AK nameAlg is not SHA-256", "nameAlg des AK ist nicht SHA-256"},
    {"AK is not a restricted signing key of the TPM", "AK ist kein eingeschränkter Signaturschlüssel des TPM"},
    {"AK is not an ECC P-256 key", "AK ist kein ECC-P-256-Schlüssel"},
    {"cannot encrypt to the EK", "Verschlüsseln an den EK nicht möglich"},
    {"cannot seal the credential", "Credential nicht versiegelbar"},
};

/*
 * "<before>…<after>": the part between is a name, a key or a path and stays
 * as it is - or, for a list of reasons, is translated piece by piece. The
 * more specific ones first: "user …: password login" before "user …".
 */
typedef struct {
  const char *before, *after, *de;
  bool nested;
} de_phrase_t;

static const de_phrase_t dePhrases[] = {
    {"no auto approval: ", "", "keine automatische Freigabe: %s", true},
    {"checks failed: ", "", "Prüfungen nicht bestanden: %s", true},
    {"on approval: ", "", "bei der Freigabe: %s", true},
    {"decided at the same time as another request: ", "", "gleichzeitig mit einer anderen Anfrage entschieden: %s", true},
    {"initdata cannot be read: ", "", "initdata nicht lesbar: %s", false},
    {"user-data cannot be read: ", "", "user-data nicht lesbar: %s", false},
    {"user entry ", " cannot be checked", "Benutzereintrag %s nicht prüfbar", false},
    {"user ", ": password login", "Benutzer %s: Passwort-Login", false},
    {"user ", ": ssh_authorized_keys is not a list", "Benutzer %s: ssh_authorized_keys ist keine Liste", false},
    {"user ", "'", "Benutzer %s'", false},
    {"unknown SSH key ", "", "unbekannter SSH-Key %s", false},
    {"contains '", "'", "enthält '%s'", false},
    {"initdata names the disk as '", "'", "initdata nennt die Disk als '%s'", false},
    {"", " matches its hash in initdata", "%s passt zum Hash in initdata", false},
    {"waiting for the customer's confirmation (request #", ")", "wartet auf Bestätigung durch den Kunden (Anfrage #%s)", false},
    {"outside the time window ", "", "außerhalb des Zeitfensters %s", false},
    {"PCR file: ", "", "PCR-Datei: %s", false},
};

static void deInto(buf_t *out, const char *en, size_t length);

/** "a; b; c", each piece on its own. */
static void deList(buf_t *out, const char *en, size_t length) {

  const char *end = en + length;

  while (en < end) {
    const char *cut = strstr(en, "; ");
    size_t piece = cut != NULL && cut < end ? (size_t)(cut - en) : (size_t)(end - en);

    deInto(out, en, piece);
    en += piece;

    if (en < end) {
      buf_t__put(out, "; ");
      en += 2;
    }
  }
}

static void deInto(buf_t *out, const char *en, size_t length) {

  for (size_t i = 0; i < sizeof deExact / sizeof deExact[0]; ++i)
    if (strlen(deExact[i][0]) == length && strncmp(deExact[i][0], en, length) == 0) {
      buf_t__put(out, deExact[i][1]);
      return;
    }

  for (size_t i = 0; i < sizeof dePhrases / sizeof dePhrases[0]; ++i) {

    const de_phrase_t *f = &dePhrases[i];
    size_t before = strlen(f->before), after = strlen(f->after);

    if (length <= before + after || strncmp(en, f->before, before) != 0 ||
        strncmp(en + length - after, f->after, after) != 0)
      continue;

    const char *mark = strstr(f->de, "%s");
    buf_t__add(out, f->de, (size_t)(mark - f->de));

    if (f->nested)
      deList(out, en + before, length - before - after);
    else
      buf_t__add(out, en + before, length - before - after);

    buf_t__put(out, mark + 2);
    return;
  }

  buf_t__add(out, en, length);
}

/**
 * The German for one of the agent's texts, HTML-escaped into `out`, with a
 * capital first letter: in the UI they stand as sentences of their own.
 */
static void deHtml(buf_t *out, const char *en) {

  buf_t plain = {0};

  deInto(&plain, en ?: "", strlen(en ?: ""));

  if (plain.at != NULL && plain.length > 0 && islower((unsigned char)plain.at[0]))
    plain.at[0] = (char)toupper((unsigned char)plain.at[0]);

  buf_t__html(out, plain.at ?: "");
  free(plain.at);
}

#endif /* WX_DE_H */
