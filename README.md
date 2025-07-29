# virusSTOP

# All rights are protected. My idea, my realization. You can use in projects with my permission and with my mention in the code and in the announcements of the program and other places where your program will be described.

I decided to try my own implementation of the mandate access in the new nucleus, otherwise colleagues are stinging on the hard work of the casoppent, installed on their systems. The nucleus version took the latter, namely Linux-6.15.8

We prepare the system:
It is necessary to set the bits of the launch permit used by all the files used. (I put it both system utilities and my own)
```
sudo find /usr/bin -xdev -type f -exec /usr/bin/setfattr -n "user.bitX" -v 1 {} \;
sudo find /sbin -xdev -type f -exec /usr/bin/setfattr -n "user.bitX" -v 1 {} \;
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

