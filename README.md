# virusSTOP


Решил опробовать свою реализацию мандатного доступа в новом ядре, а то коллеги жалаются на тяжкий труд Касперсого, установленный на их системах.

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

Мы патчим код исполнения программы и не даем ему запуститься,если не выставлен аттрибут bitX.

Пробегаемся по всем файлам в системе и выставляем нужный бит: sudo setfattr -n user.bitX -v 1 /usr/bin/base64
пересобираем ядро, в fstab для ext4 добавляем поддержку аттрибутов  'user_xattr' и перезагружаемся.

<img src="https://github.com/oditynet/virusSTOP/blob/main/result.png" title="example" width="800" />
