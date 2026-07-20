#!/bin/bash
echo '''
    ____       _      _  __ ____
   / __ \_____(_)___ | |/ // __ \___  _________  ____
  / /_/ / ___/ / __ \|   // /_/ / _ \/ ___/ __ \/ __ \
 / ____/ /  / / / / /   |/ _, _/  __/ /__/ /_/ / / / /
/_/   /_/  /_/_/ /_/_/|_/_/ |_|\___/\___/\____/_/ /_/
		Recon-Combo-By-Prince--
'''

# ==== CEK ROOT ====
if [ ! "$EUID" == 0 ]; then
	echo "Jalankan Script ini dengan root"
	exit 1
fi

echo "Recon By Prince"
read -p "[+] Masukkan Domain Target ex(www.domain.com):" domain
read -p "[+] Masukkan IP Target ex(127.0.0.1):" ip
echo "Checking Tools..."
sleep 2

# ==== LOOP CEK & INSTALL TOOLS ====
for tools in nmap gobuster nuclei subfinder dirb; do
	if ! command -v "$tools" &> /dev/null; then
		echo "[!] Tools $tools Tidak Di Temukan"
		read -p "[?] Install Tools Sekarang (Y/n):" install

		if [[ $install == y || $install == Y ]]; then
			echo "[~] Detecting OS Anda..."
			sleep 2

			if [ -f /etc/os-release ]; then
				. /etc/os-release
				OS=$ID

				case "$OS" in
					ubuntu|kali|parrot|mint|debian)
						echo "[~] Menginstall Tools Pada Linux Berbasis ($OS)..."
						sleep 2
						sudo apt install "$tools" -y
						;;
					arch|cachyos|blackarch|artix|manjaro)
						echo "[~] Menginstall Pada Linux Berbasis ($OS)..."
						if sudo pacman -Ss "$tools" &> /dev/null; then
							echo "[+] Tools tersedia di Repo anda!"
							sleep 2
							sudo pacman -S "$tools" --noconfirm
						else
							echo "[-] Tools tidak tersedia di Repo anda..."
							read -p "[?] Tambahkan Repo untuk menginstall(Y/n)" BA
							if [[ $BA == Y || $BA == y ]]; then
								echo "[+] Menambahkan Repo Blackarch..."
								sleep 2
								curl -O https://blackarch.org/strap.sh
								chmod +x strap.sh
								sudo ./strap.sh
								sudo pacman -Syu "$tools" --noconfirm
							else
								echo "[!] Tools Tidak Dapat Di Install!"
								exit 1
							fi
						fi
						;;
					*)
						echo "[!] OS tidak dikenali, Exit.."
						sleep 1
						exit 1
						;;
				esac
			fi
		fi
	fi
done

# ==== BAGIAN SCANNING (NMAP) ====
read -p "[~] Pilih Type Scanning (Nmap,masscan):" scan

	if [[ $scan == nmap || $scan == Nmap ]]; then
		cmd1="nmap $ip -T3"
		cmd2="nmap $ip -sV -sC -T3 -oN nmap-med.txt"
		cmd3="nmap $ip -sV -sC -T3 -p- -oN nmap-all.txt"

		read -p "Pilih basic/medium/allports(1,2,3):" typescan

		if [ "$typescan" == 1 ]; then
			echo "[~] Mengeksekusi Nmap Basic..."
			sleep 2
			$cmd1
		elif [ "$typescan" == 2 ]; then
			echo "[~] Mengeksekusi Nmap Medium..."
			sleep 2
			$cmd2
		elif [ "$typescan" == 3 ]; then
			echo "[~] Memulai Scanning Allports Dan Layanan..."
			sleep 2
			$cmd3
		else
			echo "[!] Pilihanmu Tidak ada"
		fi
	elif [[ $scan == masscan || $scan == Masscan ]]; then
		mcmd1="masscan $ip -p1-1000 --rate 1 -oL masscan-small.txt"
		mcmd2="masscan $ip -p1-10000 --rate 3 -oL masscan-med.txt"
		mcmd3="masscan $ip -p1-65535 --rate 5 -oL masscan-all.txt"

		read -p "Pilih basic/medium/allports(1,2,3):" typescan
		if [ "$typescan" == 1 ]; then
			echo "Memulai Masscan dengan opsi $typescan"
			$mcmd1
		elif [ "$typescan" == 2 ]; then
			echo "Memulai Masscan dengan opsi $typescan"
			$mcmd2
		elif [ "$typescan" == 3 ]; then
			echo "Memulai Masscan dengan opsi $typescan"
			$mcmd3
		else
			echo "[!] Pilihanmu Tidak ada"
		fi
	else
		echo "[!] Tipe scan tidak dikenali"
	fi

# ==== SUBDOMAIN DISCOVERY ====
sub="subfinder -d $domain -o subdomain-dis.txt"
echo "[~] Subdomain Discovery"
read -p "[?] Lakukan Pemindaian Subdomain Pada target? Y/n:" subd

if [[ $subd == y || $subd == Y ]]; then
	echo "[+] Melakukan Pemindaian Subdomain..."
	sleep 2
	eval $sub
	echo "[+] Output Di simpan di subdomain-dis.txt"
else
	echo "[!] Mengabaikan Subdomain enum"
fi

# ==== PATH DISCOVERY ====
gobus="gobuster dir -u $domain -w /usr/share/wordlists/dirb/common.txt -o gobus.txt"
dirbs="dirb https://$domain -o dirbs.txt"
echo "[~] Tahapan Dir Enum"
read -p "[?] Lakukan Directory enumeration? Y/n:" dir

if [[ $dir == y || $dir == Y ]]; then
	read -p "[?] Pilih Tools yang akan di gunakan(gobuster,dirb):" t

	if [[ $t == gobuster || $t == Gobuster ]]; then
		echo "[~] Mengunakan Gobuster..."
		sleep 2
		eval $gobus
	elif [[ $t == dirb || $t == dirbs ]]; then
		echo "[~] Menggunakan Dirb..."
		sleep 2
		eval $dirbs
	else
		echo "[~] Skipping.."
		sleep 2
	fi
fi

# ==== PINDAI TEKNOLOGI TARGET ====
techs="nuclei -u https://$domain -o nuclei-tech.txt"
echo "[~] Melakukan Pemindaian Teknologi.."
sleep 2
read -p "Detect teknologi Target? Y/n:" tech

if [[ $tech == y || $tech == Y ]]; then
	echo "[~] Memulai Memindai..."
	sleep 2
	eval $techs
else
	echo "[!] Technology Scanning Di batalkan.."
	sleep 2
fi

echo "[+] Pemindaian Selesai, Follow On Instagram @nama.disini for support"
