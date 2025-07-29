# virusSTOP

# Все права защищены. Идея моя,реализация моя. Использовать в проектах можно с моего разрешения и с моим упоминанием в коде и в анонсах программы и других местах, где будет описываться ваша программа.

Решил опробовать свою реализацию мандатного доступа в новом ядре, а то коллеги жалаются на тяжкий труд Касперсого, установленный на их системах. Версию ядра взял последнюю, а именно linux-6.15.8

Подготоавливаем систему: 
Надо выставить всем испольняемым файлам бит разрешения запуска. (Выставялем как системным утилитам, так и своим)
```
sudo find /usr/bin -xdev -type f -exec /usr/bin/setfattr -n "user.bitX" -v 1 {} \;
sudo find /sbin -xdev -type f -exec /usr/bin/setfattr -n "user.bitX" -v 1 {} \;
```
Правим код ядра:

prepare_binprm - понимает,что атрибут не вешается на вирутальные ФС и initram.

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

Следующий код устанвливаем всем новым файлам автоматом аттрибут запрещающий выполняться:

```bash
int vfs_create(struct mnt_idmap *idmap, struct inode *dir,
               struct dentry *dentry, umode_t mode, bool want_excl)
{
    // ... существующий код ...

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
    
    // ... существующий код ...

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
    
    // ... существующий код ...

    if (!error) {
        fsnotify_create(dir, dentry);
        set_bitx_attribute(idmap, dentry);
    }
    
    return error;
}
```
```bash
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
Мы патчим код исполнения программы и не даем ему запуститься,если не выставлен аттрибут bitX.

Пробегаемся по всем файлам в системе и выставляем нужный бит: 
```bash
sudo setfattr -n user.bitX -v 1 /usr/bin/base64
```

пересобираем ядро, в fstab для ext4 добавляем поддержку аттрибутов  'user_xattr' и перезагружаемся.

<img src="https://github.com/oditynet/virusSTOP/blob/main/result.png" title="example" width="800" />

Теперь я создаю программу которая имеет максильный приоритет   позволит вам из под системы установить все что угодно:

(Далее все в разработке)

```
# Сборка обертки
gcc -o bitx_launcher bitx_launcher.c

# Сборка библиотеки
gcc -shared -fPIC -o libsetbitx.so set_bitx.c -ldl

# Запуск программы
./bitx_launcher /bin/bash -c "touch test_file; ls -l test_file; getfattr -n user.bitX test_file"

# Проверка
touch test_file2
getfattr -n user.bitX test_file test_file2

```
