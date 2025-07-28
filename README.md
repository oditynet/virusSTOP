# virusSTOP


Решил опробовать свою реализацию мандатного доступа в новом ядре, а то коллеги жалаются на тяжкий труд Касперсого, установленный на их системах. Версию ядра взял последнюю, а именно linux-6.15.8

vim fs/exec.c
```bash
static int prepare_binprm(struct linux_binprm *bprm)
{
         ssize_t bitX_value = -ENODATA;
        char buffer[2] = {0};
        bitX_value = vfs_getxattr(file_mnt_idmap(bprm->file), file_dentry(bprm->file),"user.bitX", buffer, sizeof(buffer)-1);
        if (bitX_value > 0) {
                if (buffer[0] == '0') {
                printk(KERN_INFO "Execution check: %s bitX=%c\n", file_dentry(bprm->file)->d_name.name, buffer[0]);
                        return -EACCES;         }
        }
```

Следующий код устанввливаем всем новым файлам автоматом аттрибут запрещающий выполняться:

```bash
#include <linux/xattr.h>

// Добавить в начало файла
static int set_bitx_attr(struct dentry *dentry)
{
    const char value = '0'; // Значение атрибута
    int error;

    error = vfs_setxattr(&nop_mnt_idmap, dentry, "user.bitX", &value, 1, XATTR_CREATE);
    //error = vfs_setxattr(&init_user_ns, dentry, "user.bitX", &value, 1, XATTR_CREATE);
    
    if (error && error != -ENODATA && error != -EOPNOTSUPP) {
        printk(KERN_WARNING "Failed to set bitX attribute for %s: %d\n",
               dentry->d_name.name, error);
    }
    return error;
}

// Модифицировать функцию vfs_create
int vfs_create(struct mnt_idmap *idmap, struct inode *dir,
               struct dentry *dentry, umode_t mode, bool want_excl)
{
    ...
    error = dir->i_op->create(idmap, dir, dentry, mode, want_excl);
    if (!error) {
        // Установка bitX=0 после успешного создания файла
        set_bitx_attr(dentry);
    }
    ...
}
```


Мы патчим код исполнения программы и не даем ему запуститься,если не выставлен аттрибут bitX.

Пробегаемся по всем файлам в системе и выставляем нужный бит: 
```bash
sudo setfattr -n user.bitX -v 1 /usr/bin/base64
```

пересобираем ядро, в fstab для ext4 добавляем поддержку аттрибутов  'user_xattr' и перезагружаемся.

<img src="https://github.com/oditynet/virusSTOP/blob/main/result.png" title="example" width="800" />
