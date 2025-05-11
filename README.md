# DC02 - HackMyVM (Medium)

![DC02.png](DC02.png)

## Übersicht

*   **VM:** DC02
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=DC02)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 9. August 2024
*   **Original-Writeup:** https://alientec1908.github.io/DC02_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser "Medium"-Challenge war es, Root- (bzw. Domain Admin-) Zugriff auf der Maschine "DC02", einem Active Directory Domain Controller, zu erlangen. Nach initialer Enumeration und Identifizierung von AD-Diensten wurden mittels `ldapnomnom` Benutzernamen ausgelesen. Ein Passwort-Spraying-Angriff deckte schwache Credentials für den Benutzer `charlie` auf. Mit dessen Rechten wurde via AS-REP Roasting ein Hash für den Benutzer `zximena448` (Mitglied der `Backup Operators`) erlangt und offline geknackt. Als `zximena448` konnten die Registry Hives (SAM, SYSTEM, SECURITY) vom DC extrahiert werden. `secretsdump.py` wurde lokal auf die Hives angewendet, um den NTLM-Hash des Maschinenkontos (`dc01$`) zu erhalten. Dieser Hash ermöglichte einen DCSync-Angriff, wodurch die NTLM-Hashes aller Domänenbenutzer, einschließlich des Domain-Administrators, extrahiert wurden. Mit dem Administrator-Hash wurde schließlich via `wmiexec.py` eine Shell erlangt und die Root-Flag gelesen.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `nxc` (NetExec)
*   `ldapnomnom`
*   `GetUserSPNs.py` (Impacket)
*   `GetNPUsers.py` (Impacket)
*   `hashcat`
*   `smbclient`
*   `ldapdomaindump`
*   `smbserver.py` (Impacket)
*   `reg.py` (Impacket)
*   `secretsdump.py` (Impacket)
*   `wmiexec.py` (Impacket)
*   Standard Linux-Befehle (`vi`, `grep`, `mkdir`, `mv`, `cd`, `ls`, `cat`, `locate`, `cp`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "DC02" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration:**
    *   IP-Findung mittels `arp-scan` (Ziel: `192.168.2.117`, Hostname `dc02.hmv`).
    *   `nmap`-Scan identifizierte einen Windows Domain Controller (Hostname `DC01` laut NetBIOS, Domain `SUPEDECDE.LCAL`) mit offenen AD-Diensten (DNS, Kerberos, LDAP, SMB, RPC, WinRM). SMB-Signing war aktiv.
    *   Anonyme SMB-Share-Enumeration mit `nxc` schlug fehl.

2.  **Initial Access (Benutzer `charlie` und `zximena448`):**
    *   `ldapnomnom` wurde verwendet, um Benutzernamen aus dem AD zu enumerieren (u.a. `charlie`, `wreed11`).
    *   Ein Passwort-Spraying-Angriff (`nxc smb -u users.txt -p users.txt --no-brute`) auf die gefundenen Benutzer war erfolgreich für `charlie:charlie`.
    *   Kerberoasting (`GetUserSPNs.py`) mit `charlie`s Credentials scheiterte.
    *   AS-REP Roasting (`GetNPUsers.py`) mit `charlie`s Credentials fand den Benutzer `zximena448` (Mitglied der `Backup Operators`), für den Kerberos Pre-Authentication deaktiviert war, und extrahierte dessen AS-REP-Hash.
    *   Der Hash für `zximena448` wurde mit `hashcat` und `rockyou.txt` zu `internet` geknackt.

3.  **Privilege Escalation (von `zximena448` zum Domain Admin):**
    *   Mit den Credentials `zximena448:internet` wurde via `nxc smb --shares` Lese-/Schreibzugriff auf den `C$`-Share des DC bestätigt.
    *   Die User-Flag wurde via `smbclient` vom Desktop des Benutzers `zximena448` heruntergeladen.
    *   `ldapdomaindump` wurde mit `zximena448`s Credentials ausgeführt, um AD-Informationen zu sammeln.
    *   Die Registry Hives (SAM, SYSTEM, SECURITY) wurden vom DC mittels `reg.py` (Impacket) auf einen lokalen SMB-Share (`smbserver.py`) der Angreifer-Maschine extrahiert.
    *   `secretsdump.py` wurde im lokalen Modus auf die extrahierten Hives angewendet. Dies förderte u.a. den NTLM-Hash des Maschinenkontos `dc01$` (`f5ce...`) und den NTLM-Hash des lokalen Administrators zutage.
    *   Pass-the-Hash mit dem lokalen Administrator-Hash via `nxc smb` scheiterte.
    *   Pass-the-Hash mit dem Maschinenkonto-Hash `dc01$:f5ce...` via `nxc smb` war erfolgreich.

4.  **Domain Compromise (DCSync und Root-Flag):**
    *   Mit dem kompromittierten Maschinenkonto-Hash wurde ein DCSync-Angriff mittels `secretsdump.py` durchgeführt (`secretsdump.py 'SUPEDECDE.LCAL/dc01$@192.168.2.117' -hashes :f5ce...`).
    *   Dies extrahierte die NTLM-Hashes aller Domänenbenutzer, einschließlich des Domain-Administrators (`Administrator:8982...`) und des `krbtgt`-Kontos.
    *   Mit `wmiexec.py` und dem NTLM-Hash des Domain-Administrators wurde eine interaktive Shell auf dem DC erlangt.
    *   In dieser Shell wurde die Root-Flag (`root.txt`) auf dem Desktop des Administrators gefunden und ausgelesen.

## Wichtige Schwachstellen und Konzepte

*   **Schwache Passwörter:** Das Passwort `charlie` für den Benutzer `charlie` ermöglichte den initialen Zugriff.
*   **Kerberos Pre-Authentication Deaktiviert (AS-REP Roasting):** Der Benutzer `zximena448` hatte dieses Flag gesetzt, was die Extraktion seines Hashes ermöglichte.
*   **Hohe Privilegien für `Backup Operators`:** Die Mitgliedschaft von `zximena448` in dieser Gruppe ermöglichte das Auslesen der Registry Hives vom DC.
*   **Auslesen von Registry Hives:** Ermöglichte die Offline-Extraktion von Hashes, insbesondere des Maschinenkonto-Hashes.
*   **Maschinenkonto-Kompromittierung:** Der Hash des DC-Maschinenkontos (`dc01$`) erlaubte die Durchführung von DCSync.
*   **DCSync:** Ermöglichte die Extraktion aller Domänen-Passwort-Hashes, was zur vollständigen Kompromittierung der Domäne führte.
*   **Pass-the-Hash (PtH):** Wurde erfolgreich für das Maschinenkonto und später für den Domain-Administrator verwendet.

## Flags

*   **User Flag (`C:\Users\zximena448\Desktop\user.txt`):** `2fe79eb0e02ecd4dd2833cfcbbdb504c`
*   **Root Flag (`C:\Users\Administrator\Desktop\root.txt`):** `d41d8cd98f00b204e9800998ecf8427e`

## Tags

`HackMyVM`, `DC02`, `Medium`, `Active Directory`, `Windows`, `ldapnomnom`, `Passwort Spraying`, `AS-REP Roasting`, `Hashcat`, `Backup Operators`, `Registry Hives`, `secretsdump`, `Maschinenkonto`, `DCSync`, `Pass-the-Hash`, `wmiexec`, `Impacket`, `Linux` (Angreifer)
