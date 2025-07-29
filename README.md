# virusSTOP


Решил опробовать свою реализацию мандатного доступа в новом ядре, а то коллеги жалаются на тяжкий труд Касперсого, установленный на их системах. Версию ядра взял последнюю, а именно linux-6.15.8

vim fs/exec.c
```bash
#include <linux/xattr.h>
#include <linux/mnt_idmapping.h>

static int prepare_binprm(struct linux_binprm *bprm)
{
    loff_t pos = 0;
    ssize_t size;
    char value[2];
    
    struct dentry *dentry = file_dentry(bprm->file);
    struct mnt_idmap *idmap = file_mnt_idmap(bprm->file);

    // Проверка на случай ошибок
    if (!idmap) {
        printk(KERN_WARNING "Failed to get idmap for file: %s\n", dentry->d_name.name);
        return -EPERM;
    }

    size = vfs_getxattr(idmap, dentry, "user.bitX", value, sizeof(value) - 1);
    
    if (size == 1) {
        value[1] = '\0';
        if (value[0] == '0') {
            printk(KERN_WARNING "Execution denied: %s has user.bitX=0\n",
                   dentry->d_name.name);
            return -EPERM;
        }
    } else if (size == -ENODATA) { // if attrr is not install
        printk(KERN_WARNING "Execution denied: %s missing user.bitX attribute\n",
               dentry->d_name.name);
        return -EPERM;
    } else if (size < 0) {
        printk(KERN_WARNING "Execution denied: error %ld reading user.bitX for %s\n",
               size, dentry->d_name.name);
        return -EPERM;
    }
    
    memset(bprm->buf, 0, BINPRM_BUF_SIZE);
    return kernel_read(bprm->file, bprm->buf, BINPRM_BUF_SIZE, &pos);
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
