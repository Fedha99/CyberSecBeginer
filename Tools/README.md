# List Tools Development Dari saya
## Tools ini Hanya di gunakan dengan beretika!
### ⚠️ Disclaimer
Tool ini dibuat untuk tujuan edukasi dan pentest yang **legal**.
Gunakan HANYA pada:
- Sistem milik sendiri
- Target dengan izin tertulis (scope/RoE jelas)
- Lab/platform resmi (TryHackMe, HTB, dll)

Penulis tidak bertanggung jawab atas penyalahgunaan tool ini.

## FlowChart

```mermaid
flowchart TD
    A([Mulai Script]) --> B{Cek EUID == 0?}
    B -->|Bukan root| B1[Exit: jalankan dengan root]
    B -->|Root| C[Input domain & IP]
    C --> D[Loop cek tools:<br/>nmap, gobuster, nuclei,<br/>subfinder, dirb]

    D --> E{Tools tersedia?}
    E -->|Ya| F[Lanjut tools berikutnya]
    E -->|Tidak| G{Install sekarang? Y/n}
    G -->|n| F
    G -->|Y| H{Deteksi OS}
    H -->|debian/ubuntu/kali/parrot/mint| I[sudo apt install]
    H -->|arch/cachyos/blackarch/artix/manjaro| J{Tersedia di repo pacman?}
    J -->|Ya| K[sudo pacman -S]
    J -->|Tidak| L{Tambah repo Blackarch? Y/n}
    L -->|Y| M[Install strap.sh &<br/>pacman -Syu]
    L -->|n| N[Exit: gagal install]
    H -->|OS lain| O[Exit: OS tidak dikenali]
    I --> F
    K --> F
    M --> F
    F --> P{Semua tools sudah dicek?}
    P -->|Belum| D
    P -->|Sudah| Q{Pilih Type Scanning}

    Q -->|nmap| R{basic/medium/allports}
    R -->|1| S[nmap -T3]
    R -->|2| T[nmap -sV -sC -T3]
    R -->|3| U[nmap -p- allports]
    R -->|lainnya| V[Pilihan tidak ada]

    Q -->|masscan| R2{basic/medium/allports}
    R2 -->|1| S2[masscan -p1-1000 --rate 1]
    R2 -->|2| T2[masscan -p1-10000 --rate 3]
    R2 -->|3| U2[masscan -p1-65535 --rate 5]
    R2 -->|lainnya| V2[Pilihan tidak ada]

    Q -->|lainnya| W0[Tipe scan tidak dikenali]

    S --> W
    T --> W
    U --> W
    V --> W
    S2 --> W
    T2 --> W
    U2 --> W
    V2 --> W
    W0 --> W[Subdomain discovery?]

    W --> X{Lakukan? Y/n}
    X -->|Y| Y[subfinder -d domain<br/>simpan subdomain-dis.txt]
    X -->|n| Z[Skip subdomain enum]
    Y --> AA
    Z --> AA[Directory enumeration?]

    AA --> AB{Lakukan? Y/n}
    AB -->|n| AF[Skip]
    AB -->|Y| AC{Pilih tools}
    AC -->|gobuster| AD[gobuster dir<br/>simpan gobus.txt]
    AC -->|dirb| AE[dirb<br/>simpan dirbs.txt]
    AC -->|lainnya| AF
    AD --> AG
    AE --> AG
    AF --> AG[Deteksi teknologi target?]

    AG --> AH{Lakukan? Y/n}
    AH -->|Y| AI[nuclei -u domain<br/>simpan nuclei-tech.txt]
    AH -->|n| AJ[Skip technology scan]
    AI --> AK([Selesai])
    AJ --> AK
```
