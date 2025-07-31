<a name="readme-top"></a>
<div align="center">
    
<br>

# virusSTOP

<!-- SHIELD GROUP -->

# All rights are protected. My idea, my realization. You can use in projects with my permission and with my mention in the code and in the announcements of the program and other places where your program will be described.

<a name="readme-left"></a>
<div align="left">

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
Build kernel:
```
make
make modules_install
make install
mkinitcpio -p linux-custom
```

In the FSTAB for EXT4, add support for 'user_xattr' on and reboot.

<img src="https://github.com/oditynet/virusSTOP/blob/main/result.png" title="example" width="800" />

<img src="https://github.com/oditynet/virusSTOP/blob/main/result1.png" title="example" width="800" />

Now I create a program that has a maxilled priority will allow you to install anything from under the system:


```
#Build launch
gcc -o bitx_launcher bitx_launcher.c

# Build lib
gcc -shared -fPIC -o libsetbitx.so set_bitx.c -ldl

# Run
LD_PRELOAD=/home/odity/kernel/1/libsetbitx.so ./bitx_launch /bin/bash -c "touch test_file"
getfattr -n user.bitX test_file"

```
 He tested the installation of NVIDIA drivers. It was only required to give two programs of law:
 1) /home/odity/Downloads/linux-6.15.8/scripts/mod/modpost
 2) /home/odity/Downloads/linux-6.15.8/scripts/basic/fixdep


Установка обновлений сбросит все атрибуты и по этому ставим хуки:
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
echo "$(date) - Processing transaction: $PACMAN_INSTALLED_PACKAGES" >> "$LOG_FILE"

# Обработка всех установленных файлов из последней транзакции
for package in $(pacman -Qq); do
    # Получаем список файлов пакета
    pacman -Qlq "$package" | while read -r file; do
        # Проверяем, что файл существует и является исполняемым
        if [[ -f "$file" && -x "$file" ]]; then
            # Проверяем, не установлен ли уже атрибут
            if ! getfattr -n user.bitX "$file" &>/dev/null; then
                echo "Setting bitX for: $file" >> "$LOG_FILE"
                setfattr -n user.bitX -v 1 "$file"
            fi
        fi
    done
done

echo "Completed" >> "$LOG_FILE"
```


Если мы хотим запретить изменения атрибута user.bitX то нужно пропатчик в файле fs/xattr.c функцию до вида:
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

Теперь команда setfattr можно выставить любой аттрибут кроме user.bitX. Его можно будет выставить через утилиту /usr/bin/bitx_launcher из исходника bitx_launcher.c синтаксис которой '/usr/bin/bitx_launcher -v 1 file' а без аргумента она будет запускать все родительские процессы программы с битом bitX=1
```
gcc -o bitx_launch bitx_launch.c
```

Проблемы:
1) Если вы не можете выствить атрибут,то перезагружайтесь в нормальное ядро.
2) Компиляция ядра: нужно дать права файлам в подпапке ./scripts
3) /usr/bin/bitx_launcher  не имеет самоконтроль своей целостности по этому подменить его не составит проблем
