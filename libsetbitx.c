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
#include <limits.h>

#define STATUS_DIR "/tmp/bitx_status"

// Проверяем статус процесса
int is_bitX_allowed() {
    pid_t pid = getpid();
    char path[PATH_MAX];
    snprintf(path, sizeof(path), STATUS_DIR "/%d", pid);
    
    FILE *fp = fopen(path, "r");
    if (fp) {
        int value;
        if (fscanf(fp, "%d", &value) == 1) {
            fclose(fp);
            return value;
        }
        fclose(fp);
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
    
    // Устанавливаем атрибут если разрешено и файл был создан
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

// openat
int openat(int dirfd, const char *pathname, int flags, ...) {
    static int (*orig_openat)(int, const char *, int, ...) = NULL;
    if (!orig_openat) orig_openat = dlsym(RTLD_NEXT, "openat");
    
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    
    int fd;
    if (flags & O_CREAT) {
        fd = orig_openat(dirfd, pathname, flags, mode);
    } else {
        fd = orig_openat(dirfd, pathname, flags);
    }
    
    if (fd >= 0 && (flags & O_CREAT) && is_bitX_allowed()) {
        fsetxattr(fd, "user.bitX", "1", 1, 0);
    }
    return fd;
}

// openat64
int openat64(int dirfd, const char *pathname, int flags, ...) {
    static int (*orig_openat64)(int, const char *, int, ...) = NULL;
    if (!orig_openat64) orig_openat64 = dlsym(RTLD_NEXT, "openat64");
    
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    
    int fd;
    if (flags & O_CREAT) {
        fd = orig_openat64(dirfd, pathname, flags, mode);
    } else {
        fd = orig_openat64(dirfd, pathname, flags);
    }
    
    if (fd >= 0 && (flags & O_CREAT) && is_bitX_allowed()) {
        fsetxattr(fd, "user.bitX", "1", 1, 0);
    }
    return fd;
}

// mkstemp
int mkstemp(char *template) {
    static int (*orig_mkstemp)(char *) = NULL;
    if (!orig_mkstemp) orig_mkstemp = dlsym(RTLD_NEXT, "mkstemp");
    
    int fd = orig_mkstemp(template);
    if (fd >= 0 && is_bitX_allowed()) {
        fsetxattr(fd, "user.bitX", "1", 1, 0);
    }
    return fd;
}

// mkostemp
int mkostemp(char *template, int flags) {
    static int (*orig_mkostemp)(char *, int) = NULL;
    if (!orig_mkostemp) orig_mkostemp = dlsym(RTLD_NEXT, "mkostemp");
    
    int fd = orig_mkostemp(template, flags);
    if (fd >= 0 && is_bitX_allowed()) {
        fsetxattr(fd, "user.bitX", "1", 1, 0);
    }
    return fd;
}

// tmpfile
FILE *tmpfile(void) {
    static FILE *(*orig_tmpfile)(void) = NULL;
    if (!orig_tmpfile) orig_tmpfile = dlsym(RTLD_NEXT, "tmpfile");
    
    FILE *fp = orig_tmpfile();
    if (fp && is_bitX_allowed()) {
        int fd = fileno(fp);
        if (fd >= 0) {
            fsetxattr(fd, "user.bitX", "1", 1, 0);
        }
    }
    return fp;
}

// mkdir - тоже может создавать файлы через extended attributes
int mkdir(const char *pathname, mode_t mode) {
    static int (*orig_mkdir)(const char *, mode_t) = NULL;
    if (!orig_mkdir) orig_mkdir = dlsym(RTLD_NEXT, "mkdir");
    
    int result = orig_mkdir(pathname, mode);
    if (result == 0 && is_bitX_allowed()) {
        // Для директорий используем setxattr вместо fsetxattr
        setxattr(pathname, "user.bitX", "1", 1, 0);
    }
    return result;
}

// mknod
int mknod(const char *pathname, mode_t mode, dev_t dev) {
    static int (*orig_mknod)(const char *, mode_t, dev_t) = NULL;
    if (!orig_mknod) orig_mknod = dlsym(RTLD_NEXT, "mknod");
    
    int result = orig_mknod(pathname, mode, dev);
    if (result == 0 && is_bitX_allowed()) {
        setxattr(pathname, "user.bitX", "1", 1, 0);
    }
    return result;
}

// link - создает жесткую ссылку, может наследовать атрибуты
int link(const char *oldpath, const char *newpath) {
    static int (*orig_link)(const char *, const char *) = NULL;
    if (!orig_link) orig_link = dlsym(RTLD_NEXT, "link");
    
    int result = orig_link(oldpath, newpath);
    if (result == 0 && is_bitX_allowed()) {
        // Проверяем, есть ли атрибут у исходного файла
        char value[2];
        if (getxattr(oldpath, "user.bitX", value, sizeof(value)) > 0) {
            // Если у исходного файла есть атрибут, устанавливаем его для новой ссылки
            setxattr(newpath, "user.bitX", "1", 1, 0);
        }
    }
    return result;
}

// symlink
int symlink(const char *target, const char *linkpath) {
    static int (*orig_symlink)(const char *, const char *) = NULL;
    if (!orig_symlink) orig_symlink = dlsym(RTLD_NEXT, "symlink");
    
    int result = orig_symlink(target, linkpath);
    if (result == 0 && is_bitX_allowed()) {
        setxattr(linkpath, "user.bitX", "1", 1, 0);
    }
    return result;
}

// rename - может перемещать файлы между разными файловыми системами
int rename(const char *oldpath, const char *newpath) {
    static int (*orig_rename)(const char *, const char *) = NULL;
    if (!orig_rename) orig_rename = dlsym(RTLD_NEXT, "rename");
    
    // Сохраняем атрибут старого файла перед переименованием
    char value[2];
    int has_attr = (getxattr(oldpath, "user.bitX", value, sizeof(value)) > 0);
    
    int result = orig_rename(oldpath, newpath);
    
    // Если файл имел атрибут и процессу разрешено, восстанавливаем атрибут
    if (result == 0 && has_attr && is_bitX_allowed()) {
        setxattr(newpath, "user.bitX", "1", 1, 0);
    }
}
