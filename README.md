<img alt="GitHub code size in bytes" src="https://img.shields.io/github/languages/code-size/oditynet/virusSTOP"></img>
<img alt="GitHub license" src="https://img.shields.io/github/license/oditynet/virusSTOP"></img>
<img alt="GitHub commit activity" src="https://img.shields.io/github/commit-activity/m/oditynet/virusSTOP"></img>
<img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/oditynet/virusSTOP"></img>

<div align="center">
  <img src="https://github.com/oditynet/virusSTOP/blob/main/logo.png" width="250" height="auto" />
  <h1>  virusSTOP </h1>
</div>

## 📚 License
All rights are protected. My idea, my realization. You can use in projects with my permission and with my mention in the code and in the announcements of the program and other places where your program will be described.

## 📋 I can...

1. Blocking the launch of programs
2. Blocking the launch of scripts as an executable file and a file passed as an argument to the interpreter (bash, awk, sh, python and etc.)  WARNING: This is a complex implementation. It is in development and testing.
3. You can set the attribute only through your program (work with the user.bitX attribute is blocked via setfattr )

## 🛠️ Prepare 

I decided to try my own implementation of the mandate access in the new nucleus, otherwise colleagues are stinging on the hard work of the casoppent, installed on their systems. The nucleus version took the latter, namely Linux-6.15.8

We prepare the system:
It is necessary to set the bits of the launch permit used by all the files used. (I put it both system utilities and my own)
```
sudo find /usr/bin -xdev -type f -exec /usr/bin/setfattr -n "user.bitX" -v 1 {} \;
sudo find /sbin -xdev -type f -exec /usr/bin/setfattr -n "user.bitX" -v 1 {} \;
```

Used patch:
```
cd linux/fs
 patch -p1 < exec.patch
 patch -p1 < namei.patch
 patch -p1 < xattr.patch
```

Prepare_binPrm - understands that the attribute is not hanged on virus and Initram.

vim fs/exec.c
```bash

#include <linux/xattr.h>
#include <linux/mnt_idmapping.h>
#include <linux/fs.h>
#include <linux/fs_types.h>

static int prepare_binprm(struct linux_binprm *bprm)
{
    loff_t pos = 0;
    ssize_t size;
    char value[2];
    struct dentry *dentry;
    struct mnt_idmap *idmap;
    struct inode *inode;
    const char *fstype;

    dentry = file_dentry(bprm->file);
    idmap = file_mnt_idmap(bprm->file);
    inode = d_inode(dentry);
    fstype = inode->i_sb->s_type->name;

    // Критическое исключение для tmpfs и других виртуальных ФС
    if (strcmp(fstype, "tmpfs") == 0 ||
        strcmp(fstype, "ramfs") == 0 ||
        strcmp(fstype, "devtmpfs") == 0 ||
        strcmp(fstype, "proc") == 0 ||
        strcmp(fstype, "sysfs") == 0 ||
        strcmp(fstype, "cgroup") == 0) {
        goto read_file;
    }

    if (WARN_ON(!idmap)) {
        printk(KERN_ERR "[bitX] Failed to get idmap for file: %s\n", dentry->d_name.name);
        return -EPERM;
    }

    size = vfs_getxattr(idmap, dentry, "user.bitX", value, sizeof(value) - 1);
    
    if (size == 1) {
        value[1] = '\0';
        if (value[0] == '0') {
            printk(KERN_WARNING "[bitX] Execution denied: %s has user.bitX=0\n",
                   dentry->d_name.name);
            return -EPERM;
        }
    } else if (size == -ENODATA) {
        printk(KERN_INFO "[bitX] Execution not allowed (no bitX): %s\n", dentry->d_name.name);
         return -EPERM;
    } else if (size < 0) {
        printk(KERN_WARNING "[bitX] Error %ld reading user.bitX for %s (FS: %s)\n",
               size, dentry->d_name.name, fstype);
        goto read_file;
    }

read_file:
    memset(bprm->buf, 0, BINPRM_BUF_SIZE);
    return kernel_read(bprm->file, bprm->buf, BINPRM_BUF_SIZE, &pos);
}
```

The next code sets all new files by the ATRIBUT ATRIBUT prohibiting to execute:

```bash
int vfs_create(struct mnt_idmap *idmap, struct inode *dir,
               struct dentry *dentry, umode_t mode, bool want_excl)
{
    // ... 

    if (!error) {
        fsnotify_create(dir, dentry);
        set_bitx_attribute(idmap, dentry); // Новая функция
    }

    return error;
}
```
```bash
int vfs_mknod(struct mnt_idmap *idmap, struct inode *dir,
              struct dentry *dentry, umode_t mode, dev_t dev)
{
    int error;
    
    // ... 

    if (!error) {
        fsnotify_create(dir, dentry);
        set_bitx_attribute(idmap, dentry);
    }
    
    return error;
}
```
```bash
int vfs_symlink(struct mnt_idmap *idmap, struct inode *dir,
                struct dentry *dentry, const char *oldname)
{
    int error;
    
    // ...

    if (!error) {
        fsnotify_create(dir, dentry);
        set_bitx_attribute(idmap, dentry);
    }
    
    return error;
}
```
```bash

#include <linux/xattr.h>
static void set_bitx_attribute(struct mnt_idmap *idmap, struct dentry *dentry)
{
    const char *name = "user.bitX";
    const char *value = "0";
    struct inode *inode = d_inode(dentry);
    const char *fstype;
    
    if (!inode) return;
    
    fstype = inode->i_sb->s_type->name;
    
    // Исключаем виртуальные ФС
    if (strcmp(fstype, "tmpfs") == 0 ||
        strcmp(fstype, "ramfs") == 0 ||
        strcmp(fstype, "devtmpfs") == 0 ||
        strcmp(fstype, "proc") == 0 ||
        strcmp(fstype, "sysfs") == 0 ||
        strcmp(fstype, "cgroup") == 0) {
        return;
    }
    
    // Только для обычных файлов
    if (!S_ISREG(inode->i_mode)) {
        return;
    }
    
    int xerr = vfs_setxattr(idmap, dentry, name, value, strlen(value), XATTR_CREATE);
    
    if (xerr) {
        if (xerr != -EOPNOTSUPP && xerr != -ENOTSUP) {
            printk(KERN_INFO "[bitX] Set bitX failed for %s (err=%d, FS=%s)\n",
                   dentry->d_name.name, xerr, fstype);
        }
    } else {
        printk(KERN_INFO "[bitX] Set bitX=0 for new file: %s (FS=%s)\n",
               dentry->d_name.name, fstype);
    }
}
```

## Build kernel:
```
make
make modules_install
make install
mkinitcpio -p linux-custom (mkinitcpio -k 6.15.8  -g /boot/initramfs-linux1.img)
```

In the FSTAB for EXT4, add support for 'user_xattr' on and reboot.

<img src="https://github.com/oditynet/virusSTOP/blob/main/result.png" title="example" width="800" />

<img src="https://github.com/oditynet/virusSTOP/blob/main/result1.png" title="example" width="800" />

<img src="https://github.com/oditynet/virusSTOP/blob/main/kernel_in_work.gif" title="example" width="800" />

Now I create a program that has a maxilled priority will allow you to install anything from under the system:


```
#Build launch
gcc -o bitx_launcher bitx_launcher.c

# Build lib
gcc -shared -fPIC -o libsetbitx.so set_bitx.c -ldl

# Run
./bitx_launch /bin/bash -c "touch test_file"
getfattr -n user.bitX test_file"

```
 He tested the installation of NVIDIA drivers. It was only required to give two programs of law:
 1) /home/odity/Downloads/linux-6.15.8/scripts/mod/modpost
 2) /home/odity/Downloads/linux-6.15.8/scripts/basic/fixdep

Installing updates will reset all attributes, so we set hooks:

```
# /usr/share/libalpm/hooks/set-bitx.hook 
[Trigger]
Operation = Install
Operation = Upgrade
Type = Package
Target = *

[Action]
Description = Setting user.bitX attribute for executables...
When = PostTransaction
Exec = /usr/local/bin/set-bitx-for-new-files.sh
Depends = attr
```

```
#/usr/local/bin/set-bitx-for-new-files.sh

#!/bin/bash

# Логирование
LOG_FILE="/var/log/pacman-bitx.log"
echo "$(date) - Starting bitX attribute processing" >> "$LOG_FILE"

# Получаем текущую дату в формате, как в pacman.log (например: [2023-10-01])
TODAY=$(date +'%Y-%m-%d')

# Извлекаем пакеты, установленные/обновлённые сегодня
PACMAN_NEW_PKGS=$(grep -E "(installed|upgraded)" /var/log/pacman.log | grep $TODAY|awk '{print $4}' | sort -u)

if [[ -z "$PACMAN_NEW_PKGS" ]]; then
    echo "$(date) - No new packages found for today" >> "$LOG_FILE"
    exit 0
fi

echo "$(date) - Processing packages: $PACMAN_NEW_PKGS" >> "$LOG_FILE"

# Обработка только новых пакетов
for package in $PACMAN_NEW_PKGS; do
    # Получаем список файлов пакета
    pacman -Qlq "$package" 2>/dev/null | while read -r file; do
        # Проверяем, что файл существует и является исполняемым
        if [[ -f "$file" && -x "$file" ]]; then
            # Проверяем, не установлен ли уже атрибут
            if ! getfattr -n user.bitX "$file" &>/dev/null; then
                echo "Setting bitX for: $file" >> "$LOG_FILE"
                /usr/bin/bitx_launcher -v 1 "$file"
            fi
        fi
    done
done

echo "$(date) - Completed" >> "$LOG_FILE"
```

If we want to prohibit changes to the user.bitX attribute, we need to patch the function in the fs/xattr.c file to the following form:

```
       const char *allowed_exec = "/usr/bin/bitx_launcher";

       // Отслеживаем только user.bitX
       if (strcmp(name, "user.bitX") == 0) {
               // Получаем путь к исполняемому файлу процесса
               exe_file = get_task_exe_file(current);
               if (!exe_file) {
                       return -EPERM;
               }

               char *path = d_path(&exe_file->f_path, exe_path, sizeof
(exe_path));
               fput(exe_file);

               // Если это не bitx_launcher — запрещаем
               if (IS_ERR(path) || strcmp(path, allowed_exec) != 0) {
                       printk(KERN_WARNING "[bitX] Unauthorized attempt to set user.bitX from %s\n", path);
                       return -EPERM;
               }

               // Логируем значение (если нужно)
               if (size == 1 && (*(char *)value == '0' || *(char *)value == '1')) {
                       printk(KERN_INFO "[bitX] user.bitX set1 to %c by %s\n", *(char *)value, path);
               }
       }

        if (delegated_inode) {
                error = break_deleg_wait(&delegated_inode);
                if (!error)
                        goto retry_deleg;
        }
        if (value != orig_value)
                kfree(value);

        return error;
}
```

Now the setfattr command can set any attribute except user.bitX. It can be set via the /usr/bin/bitx_launcher utility from the bitx_launcher.c source code, the syntax of which is '/usr/bin/bitx_launcher -v 1 file' and without an argument it will launch all parent processes of the program with the bitX=1 bit.

```
gcc -o bitx_launch bitx_launch.c
```

## Problems 

1) If you can't set the attribute, then reboot into a normal kernel.
2) Compiling the kernel: you need to give rights to files in the ./scripts subfolder
3) /usr/bin/bitx_launcher does not have self-control of its integrity, so replacing it will not be a problem
