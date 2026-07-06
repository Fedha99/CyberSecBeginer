#ifndef COMMON_H
#define COMMON_H

// Semua header standar, makro, struktur, dan deklarasi global
#include <stdio.h>
// ... (salin semua #include dan definisi yang ada di kode Anda)
// Deklarasi extern untuk variabel global
extern Config cfg;
extern pthread_mutex_t log_lock, prt_lock;
// Fungsi utilitas
void trim(char *s);
int safe_runcmd(const char *cmd);
void get_safe_input(const char *prompt, char *buffer, size_t size);
// ... dst
#endif
