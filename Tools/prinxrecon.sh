#!/bin/bash
echo '''
    ____       _      _  __ ____                      
   / __ \_____(_)___ | |/ // __ \___  _________  ____ 
  / /_/ / ___/ / __ \|   // /_/ / _ \/ ___/ __ \/ __ \
 / ____/ /  / / / / /   |/ _, _/  __/ /__/ /_/ / / / /
/_/   /_/  /_/_/ /_/_/|_/_/ |_|\___/\___/\____/_/ /_/ 
		Recon-Combo-By-Prince--                                                      
'''

# Cek root. $EUID sudah benar, ditutup "fi" (bukan "done")
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
for tools in nmap gobuster nuclei subfinder dirb httpx; do
	if ! command -v "$tools" &> /dev/null; then
		echo "[!] Tools $tools Tidak Di Temukan"
		read -p "[?] Install Tools Sekarang (Y/n)?" install

		if [[ $install == y || $install == Y ]]; then
			echo "[~] Detecting OS Anda..."
			sleep 2

			if [ -f /etc/os-release ]; then
				. /etc/os-release
				OS=$ID

				# case ditutup "esac", bukan "done"
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
					# Pattern default kalau OS gak dikenali
					# (dulu ini "echo ... exit 1 done" nyasar di luar pattern, sekarang jadi *) yang benar
					*)
						echo "[!] OS tidak dikenali, Exit.."
						sleep 1
						exit 1
						;;
				esac   # <- tutup case
			fi         # <- tutup if -f /etc/os-release
		fi             # <- tutup if install Y/n
	fi                 # <- tutup if command -v tools
done                   # <- tutup for tools (dulu ini "done" nyasar duluan sebelum loop selesai)

# ==== BAGIAN SCANNING, DILUAR LOOP TOOLS ====
# (dulu bagian ini nyangkut DI DALAM loop for, sekarang dipindah keluar)
read -p "[~] Pilih Type Scanning (Nmap,masscan)" scan

if [[ $scan == nmap || $scan == Nmap ]]; then
	# Nama variabel gak boleh diawali angka & gak boleh ada spasi di sekitar "="
	# 1 = "..."   -->   cmd1="..."
	cmd1="nmap $ip -T3"
	cmd2="nmap $ip -sV -sC -T3 -oN nmap-med.txt"
	cmd3="nmap $ip -sV -sC -T3 -p- -oN nmap-all.txt"

	read -p "Pilih basic/medium/allports(1,2,3):" typescan

	if [ "$typescan" == 1 ]; then
		echo "[~] Mengeksekusi Nmap Basic..."
		sleep 2
		$cmd1          # dulu "exec $1" -> exec akan mematikan shell, cukup panggil biasa
	elif [ "$typescan" == 2 ]; then
		echo "[~] Mengeksekusi Nmap Medium..."
		sleep 2
		$cmd2
	elif [ "$typescan" == 3 ]; then
		echo "[~] Memulai Scanning Allports Dan Layanan..."
		sleep 2
		$cmd3
	else
		echo "Pilihanmu Tidak ada"
	fi
fi


#===Discovery===#

gobus="gobuster dir -u http://$domain -w /usr/share/wordlists/dirb/common.txt"
dirbs="dirb http://$domain"

echo "[~] Discovery Domain Atau IP"
read -p "Masukkan nama tools yang ingin anda gunakan (tersedia:dirb,gobuster,ALL)" discovery
	if [[ $discovery == gobuster || $discovery == Gobuster ]]; then
		echo "[~] Menggunakan Tools $discovery"
		sleep 2
		eval $gobus
	elif [[ $discovery == dirb || $discovery == Dirb ]]; then
		echo "[~] Menggunakan Tools $discovery"
		sleep 2
		eval $dirbs
	elif [[ $discovery == ALL || $discovery == All || $discovery == all ]]; then
		echo "[~] Menggunakan Semua Tools..."
		sleep 2
		eval $gobus
		eval $dirbs
	else
		echo "[!] Tools Tidak Tersedia, Tambahkan sendiri di script"
		exit 1
	fi

#===subDomain-Finder===#

echo "[~] Subdomain Discovery"
read -p "Lakukan Subdomain Discovery? Y/n" subd
  if [[ $subd == Y || $subd == y ]]; then
    echo "Mencoba menemukan Subdomain..."
    subfinder -d $domain -o subdomain-dis.txt
  else
    echo "[!] Pemindaian tidak dilakukan"
  fi

#====Detect Technology====#
echo "[~] Melakukan Pemindaian Teknologi $domain"
read -p "Pindai Teknologi $domain? Y/n" http-det

		
