<img alt="GitHub code size in bytes" src="https://img.shields.io/github/languages/code-size/oditynet/virusSTOP"></img>
<img alt="GitHub license" src="https://img.shields.io/github/license/oditynet/virusSTOP"></img>
<img alt="GitHub commit activity" src="https://img.shields.io/github/commit-activity/m/oditynet/virusSTOP"></img>
<img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/oditynet/virusSTOP"></img>
![Build Status](https://github.com/oditynet/virusSTOP/actions/workflows/c-cpp.yml/badge.svg)

<div align="center">
  <img src="https://github.com/oditynet/virusSTOP/blob/main/logo.png" width="250" height="auto" />
  <h1>  virusSTOP </h1>
</div>

## 📚 License
All rights are protected. My idea, my realization. You can use in projects with my permission and with my mention in the code and in the announcements of the program and other places where your program will be described.

## 📋 I can...

1. Blocking the launch of programs
2. Blocking the launch of scripts as an executable file and a file passed as an argument to the interpreter (bash, awk, sh, python and etc.) FAILED: It is not work :( May be you can do it?
3. You can set the attribute only through your program (work with the user.bitX attribute is blocked via setfattr )

## 🛠️ Prepare 

I decided to try my own implementation of the mandate access in the new nucleus, otherwise colleagues are stinging on the hard work of the casoppent, installed on their systems. The nucleus version took the latter, namely Linux-6.15.8+ (6.17.7 test is done)

We prepare the system:
It is necessary to set the bits of the launch permit used by all the files used. (I put it both system utilities and my own)
```
if command -v pacman >/dev/null; then
    pacman -Qlq | while read file; do
        if [[ -f "$file" || -d "$file" ]]; then
            /usr/bin/setfattr -n "user.bitX" -v "1" "$file" 2>/dev/null
        fi
    done
fi
```

Used patch:
```
cd linux/fs
 patch -p1 < exec.patch
 patch -p1 < namei.patch
 patch -p1 < xattr.patch
```

## 🌪 Build kernel:
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


In xattr.c i add in  white list bitx_launcher and systemd because it was set bitX 
```
systemd[1]: Hostname set to <viva>.
авг 07 10:42:47 viva kernel: Unauthorized attempt to set user.bitX from /usr/lib/systemd/systemd
авг 07 10:42:47 viva kernel: [bitX] Unauthorized1 attempt to set user.bitX from /usr/lib/systemd>
авг 07 10:42:47 viva systemd[1]: bpf-restrict-fs: LSM BPF program attached
```
```
#Build launch
gcc -o bitx_launcher bitx_launcher.c

# Build lib
gcc -shared -fPIC -o libsetbitx.so libsetbitx.c -ldl

# Run
./bitx_launch /bin/bash -c "touch test_file"
setfattr -n user.bitX -v 1 bitx_launcher"
sudo cp libsetbitx.so /usr/lib/
sudo cp bitx_launcher /usr/bin/

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
Exec = sudo sh /usr/local/bin/set-bitx-for-new-files.sh
Depends = attr
```

```
sudo chmod +x /usr/local/bin/set-bitx-for-new-files.sh
```

```
#!/bin/bash
# Лог файл
LOG_FILE="/var/log/bitx-setup.log"
TODAY=$(date +%Y-%m-%d)

{
    echo "=== $(date) ==="
    echo "Setting bitX attribute on packages updated/installed today ($TODAY)"
    
    # Получаем список пакетов, которые были обновлены или установлены сегодня
    UPDATED_PKGS=$(grep "\[ALPM\] \(upgraded\|installed\) " /var/log/pacman.log | grep "$TODAY" | \
                  awk '{print $4}' | sort -u)
    
    if [[ -z "$UPDATED_PKGS" ]]; then
        echo "No packages were updated or installed today."
        exit 0
    fi
    
    echo "Packages to process:"
    echo "$UPDATED_PKGS"
    echo ""
    
    # Обрабатываем каждый пакет
    for pkg in $UPDATED_PKGS; do
        echo "Processing package: $pkg"
        
        # Получаем список файлов пакета
        pacman -Ql "$pkg" 2>/dev/null | while read pkg_name file; do
            if [[ -f "$file" || -d "$file" ]]; then
                # Устанавливаем атрибут bitX=1
                if /usr/bin/setfattr -n "user.bitX" -v "1" "$file" 2>/dev/null; then
                    echo "  SET: $file"
                else
                    echo "  ERROR: $file"
                fi
            fi
        done
    done
    
    echo "Completed processing $(echo "$UPDATED_PKGS" | wc -w) packages."
    echo ""
} >> "$LOG_FILE" 2>&1

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

## ☯ Problems 

1) If you can't set the attribute, then reboot into a normal kernel.
2) Compiling the kernel: you need to give rights to files in the ./scripts subfolder
3) /usr/bin/bitx_launcher does not have self-control of its integrity, so replacing it will not be a problem
4) 
# Hack
- find /home/odity/Downloads/linux-6.17.7/scripts/ -type f -exec sudo bitx_launcher -v 1 {} \;
