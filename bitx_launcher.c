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
        fscanf(fp, "%d", &value);
        fclose(fp);
        return value;
    }
    return 0; // По умолчанию запрещено
}

// Удаляем статус при завершении
void cleanup_status(pid_t pid) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), STATUS_DIR "/%d", pid);
    unlink(path);
}

// Получаем путь к библиотеке
char* get_lib_path() {
    static char lib_path[PATH_MAX];
    if (lib_path[0] == '\0') {
        char exe_path[PATH_MAX];
        ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
        if (len > 0) {
            exe_path[len] = '\0';
            char *last_slash = strrchr(exe_path, '/');
            if (last_slash) {
                *last_slash = '\0';
                snprintf(lib_path, sizeof(lib_path), "%s/libsetbitx.so", exe_path);
            }
        }
    }
    return lib_path;
}

void trace_child(pid_t pid);

void handle_new_process(pid_t pid) {
    printf("\n[!] New process detected: PID=%d\n", pid);
    printf("[?] Set bitX to 0 or 1? (0/1): ");
    fflush(stdout);

    char choice[MAX_CHOICE_LEN];
    fgets(choice, MAX_CHOICE_LEN, stdin);
    
    int bitx_val = atoi(choice);
    set_bitX(pid, bitx_val);
    
    if (bitx_val == 1) {
        printf("[+] Process %d allowed (bitX=1)\n", pid);
    } else {
        printf("[-] Process %d restricted (bitX=0)\n", pid);
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
            
            if (sig == (SIGTRAP | 0x80)) {
                // System call handling
            }
            else if (sig == SIGTRAP) {
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

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program> [args...]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Инициализируем директорию статусов
    init_status_dir();
    
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        // Child process - the program being launched
        char *lib_path = get_lib_path();
        if (lib_path[0]) {
            char *ld_preload = getenv("LD_PRELOAD");
            char new_preload[PATH_MAX * 2];
            
            if (ld_preload) {
                snprintf(new_preload, sizeof(new_preload), "%s:%s", lib_path, ld_preload);
            } else {
                snprintf(new_preload, sizeof(new_preload), "%s", lib_path);
            }
            setenv("LD_PRELOAD", new_preload, 1);
        }

        prctl(PR_SET_PDEATHSIG, SIGKILL);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        
        execvp(argv[1], argv + 1);
        perror("execvp");
        exit(EXIT_FAILURE);
    } else {
        // Parent process - tracer
        waitpid(pid, NULL, 0);  // Wait for SIGSTOP
        
        set_bitX(pid, 1);  // Allow main process
        ptrace(PTRACE_CONT, pid, 0, 0);
        trace_child(pid);
        cleanup_status(pid);
    }

    return EXIT_SUCCESS;
}
