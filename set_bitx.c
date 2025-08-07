#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/xattr.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#define STATUS_DIR "/tmp/bitx_status"

// Проверяем статус процесса
int is_bitX_allowed() {
    pid_t pid = getpid();
    char path[PATH_MAX];
    snprintf(path, sizeof(path), STATUS_DIR "/%d", pid);
    
    FILE *fp = fopen(path, "r");
    if (fp) {
        int value;
        fscanf(fp, "%d", &value);
        fclose(fp);
        return value;
    }
    return 0; // Default deny
}

// Обработчик для создания файлов
static int handle_creation(const char *pathname, int flags, mode_t mode, int (*orig_func)(const char *, int, ...)) {
    int fd;
    
    if (flags & O_CREAT) {
        fd = orig_func(pathname, flags, mode);
    } else {
        fd = orig_func(pathname, flags);
    }
    
    // Устанавливаем атрибут если разрешено
    if (fd >= 0 && (flags & O_CREAT) && is_bitX_allowed()) {
        fsetxattr(fd, "user.bitX", "1", 1, 0);
    }
    return fd;
}

// open
int open(const char *pathname, int flags, ...) {
    static int (*orig_open)(const char *, int, ...) = NULL;
    if (!orig_open) orig_open = dlsym(RTLD_NEXT, "open");
    
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    
    return handle_creation(pathname, flags, mode, orig_open);
}

// open64
int open64(const char *pathname, int flags, ...) {
    static int (*orig_open64)(const char *, int, ...) = NULL;
    if (!orig_open64) orig_open64 = dlsym(RTLD_NEXT, "open64");
    
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    
    return handle_creation(pathname, flags, mode, orig_open64);
}

// creat
int creat(const char *pathname, mode_t mode) {
    static int (*orig_creat)(const char *, mode_t) = NULL;
    if (!orig_creat) orig_creat = dlsym(RTLD_NEXT, "creat");
    
    int fd = orig_creat(pathname, mode);
    if (fd >= 0 && is_bitX_allowed()) {
        fsetxattr(fd, "user.bitX", "1", 1, 0);
    }
    return fd;
}
