#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/xattr.h>

#define MAX_CHOICE_LEN 16
#define STATUS_DIR "/tmp/bitx_status"

// Создаем директорию для хранения статусов
void init_status_dir() {
    mkdir(STATUS_DIR, 0700);
}

// Устанавливаем статус процесса
void set_bitX(pid_t pid, int value) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), STATUS_DIR "/%d", pid);
    
    FILE *fp = fopen(path, "w");
    if (fp) {
        fprintf(fp, "%d", value);
        fclose(fp);
        printf("Set bitX=%d for PID=%d\n", value, pid);
    } else {
        perror("Failed to set bitX status");
    }
}

// Получаем статус процесса
int get_bitX(pid_t pid) {
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
    return 0; // По умолчанию запрещено
}

// Удаляем статус при завершении
void cleanup_status(pid_t pid) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), STATUS_DIR "/%d", pid);
    unlink(path);
}

// Функция для установки/снятия атрибута
int set_bitx_attr(const char *filename, int value) {
    if (value == 1) {
        int result = setxattr(filename, "user.bitX", "1", 1, 0);
        if (result == 0) {
            printf("Successfully set user.bitX=1 on %s\n", filename);
        } else {
            perror("Failed to set user.bitX=1");
        }
        return result;
    } else {
        int result = removexattr(filename, "user.bitX");
        if (result == 0) {
            printf("Successfully removed user.bitX from %s\n", filename);
        } else if (errno == ENODATA) {
            printf("Attribute user.bitX not found on %s\n", filename);
        } else {
            perror("Failed to remove user.bitX");
        }
        return result;
    }
}

void trace_child(pid_t pid);

void handle_new_process(pid_t pid) {
    printf("\n[!] New process detected: PID=%d\n", pid);
    printf("[?] Set bitX to 0 or 1? (0/1): ");
    fflush(stdout);

    char choice[MAX_CHOICE_LEN];
    if (fgets(choice, MAX_CHOICE_LEN, stdin)) {
        int bitx_val = atoi(choice);
        set_bitX(pid, bitx_val);
        
        if (bitx_val == 1) {
            printf("[+] Process %d allowed (bitX=1)\n", pid);
        } else {
            printf("[-] Process %d restricted (bitX=0)\n", pid);
        }
    }
}

void trace_child(pid_t pid) {
    int status;
    ptrace(PTRACE_SETOPTIONS, pid, 0, 
           PTRACE_O_TRACESYSGOOD |
           PTRACE_O_TRACEFORK |
           PTRACE_O_TRACEVFORK |
           PTRACE_O_TRACECLONE |
           PTRACE_O_TRACEEXEC |
           PTRACE_O_EXITKILL);
    
    while (1) {
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        if (waitpid(pid, &status, 0) < 0) {
            if (errno == ECHILD) break;
            perror("waitpid");
            break;
        }
        
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            printf("[*] Process %d exited\n", pid);
            cleanup_status(pid);
            break;
        }
        
        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            unsigned long event = (unsigned long)status >> 16;
            
            if (sig == SIGTRAP) {
                if (event == PTRACE_EVENT_FORK ||
                    event == PTRACE_EVENT_VFORK ||
                    event == PTRACE_EVENT_CLONE) {
                    
                    unsigned long child_pid;
                    ptrace(PTRACE_GETEVENTMSG, pid, 0, &child_pid);
                    
                    if (ptrace(PTRACE_ATTACH, child_pid, 0, 0) == 0) {
                        waitpid(child_pid, &status, 0);
                        handle_new_process(child_pid);
                        
                        // Resume child process
                        ptrace(PTRACE_DETACH, child_pid, 0, 0);
                    }
                }
                else if (event == PTRACE_EVENT_EXEC) {
                    handle_new_process(pid);
                }
            }
        }
    }
}

void print_usage(const char *program_name) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s [-v 0|1] <filename>          - set/remove bitX attribute on file\n", program_name);
    fprintf(stderr, "  %s <program> [args...]          - launch program with bitX control\n", program_name);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -v 0|1             Value: 1 to set, 0 to remove attribute\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s /tmp/file.txt              # Set bitX=1 on file\n", program_name);
    fprintf(stderr, "  %s -v 1 /tmp/file.txt         # Set bitX=1 on file\n", program_name);
    fprintf(stderr, "  %s -v 0 /tmp/file.txt         # Remove bitX from file\n", program_name);
    fprintf(stderr, "  %s /bin/touch /tmp/test.txt   # Launch program\n", program_name);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    // Инициализируем директорию статусов
    init_status_dir();
    
    // Проверяем, если первый аргумент -v (установка атрибута)
    int set_attr_mode = 0;
    int value = 1; // default value
    const char *target = NULL;
    
    if (strcmp(argv[1], "-v") == 0) {
        // Формат: bitx_launcher -v 0|1 <filename>
        if (argc < 4) {
            fprintf(stderr, "Error: -v requires value and filename\n");
            print_usage(argv[0]);
            exit(EXIT_FAILURE);
        }
        value = atoi(argv[2]);
        if (value != 0 && value != 1) {
            fprintf(stderr, "Error: -v value must be 0 or 1\n");
            exit(EXIT_FAILURE);
        }
        target = argv[3];
        set_attr_mode = 1;
    } else if (argc == 2) {
        // Формат: bitx_launcher <filename> (установка атрибута по умолчанию)
        target = argv[1];
        set_attr_mode = 1;
    }
    
    // Режим установки атрибута на файл
    if (set_attr_mode) {
        return set_bitx_attr(target, value) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    
    // Режим запуска программы
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        // Child process - the program being launched
        char *ld_preload = getenv("LD_PRELOAD");
        char new_preload[PATH_MAX * 2];
        
        // Добавляем нашу библиотеку в LD_PRELOAD
        const char *lib_path = "/usr/lib/libsetbitx.so";
        if (access(lib_path, F_OK) != 0) {
            // Если библиотеки нет в /usr/lib, используем относительный путь
            lib_path = "./libsetbitx.so";
        }
        
        if (ld_preload) {
            snprintf(new_preload, sizeof(new_preload), "%s:%s", lib_path, ld_preload);
        } else {
            snprintf(new_preload, sizeof(new_preload), "%s", lib_path);
        }
        setenv("LD_PRELOAD", new_preload, 1);

        prctl(PR_SET_PDEATHSIG, SIGKILL);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        
        execvp(argv[1], argv + 1);
        perror("execvp");
        exit(EXIT_FAILURE);
    } else {
        // Parent process - tracer
        int status;
        waitpid(pid, &status, 0);  // Wait for SIGSTOP
        
        set_bitX(pid, 1);  // Allow main process by default
        printf("[+] Main process %d allowed (bitX=1)\n", pid);
        ptrace(PTRACE_CONT, pid, 0, 0);
        trace_child(pid);
        cleanup_status(pid);
    }

    return EXIT_SUCCESS;
}
