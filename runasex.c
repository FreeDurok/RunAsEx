#include <windows.h>
#include <stdio.h>

#define SE_IMPERSONATE_NAME_W L"SeImpersonatePrivilege"
#define SE_ASSIGNPRIMARYTOKEN_NAME_W L"SeAssignPrimaryTokenPrivilege"

BOOL HasPrivilege(LPCWSTR privName) {
    HANDLE hToken;
    LUID luid;
    PRIVILEGE_SET privs;
    BOOL result = FALSE;
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;
    
    if (!LookupPrivilegeValueW(NULL, privName, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }
    
    privs.PrivilegeCount = 1;
    privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
    privs.Privilege[0].Luid = luid;
    privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    PrivilegeCheck(hToken, &privs, &result);
    CloseHandle(hToken);
    return result;
}

BOOL EnablePrivilege(LPCWSTR privName) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;
    
    if (!LookupPrivilegeValueW(NULL, privName, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return FALSE;
    }
    
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hToken);
    return ok && err == ERROR_SUCCESS;
}

BOOL TryLogonAndRun(wchar_t* user, wchar_t* domain, wchar_t* pass, wchar_t* cmd, 
                    DWORD logonType, const char* typeName, PROCESS_INFORMATION* pi) {
    printf("[*] Tentativo: LogonUser (%s) + CreateProcessWithTokenW\n", typeName);
    
    HANDLE hToken;
    if (!LogonUserW(user, domain, pass, logonType, LOGON32_PROVIDER_DEFAULT, &hToken)) {
        printf("    [-] LogonUser fallito: %lu\n", GetLastError());
        return FALSE;
    }
    printf("    [+] LogonUser OK\n");
    
    STARTUPINFOW si = { sizeof(si) };
    
    if (CreateProcessWithTokenW(hToken, LOGON_WITH_PROFILE, 
            NULL, cmd, CREATE_NEW_CONSOLE, NULL, NULL, &si, pi)) {
        CloseHandle(hToken);
        return TRUE;
    }
    printf("    [-] CreateProcessWithTokenW fallito: %lu\n", GetLastError());
    CloseHandle(hToken);
    return FALSE;
}

BOOL TryWithLogonW(wchar_t* user, wchar_t* domain, wchar_t* pass, wchar_t* cmd, PROCESS_INFORMATION* pi) {
    printf("[*] Tentativo: CreateProcessWithLogonW\n");
    
    STARTUPINFOW si = { sizeof(si) };
    
    if (CreateProcessWithLogonW(user, domain, pass, LOGON_WITH_PROFILE,
            NULL, cmd, CREATE_NEW_CONSOLE, NULL, NULL, &si, pi)) {
        return TRUE;
    }
    printf("    [-] Fallito: %lu\n", GetLastError());
    return FALSE;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("=== RunAsEx ===\n\n");
        printf("Uso: %s <dominio\\utente> <password> <comando> [args...]\n\n", argv[0]);
        return 1;
    }
    
    wchar_t domain[256] = L".";
    wchar_t username[256] = {0};
    wchar_t password[256] = {0};
    wchar_t cmdline[4096] = {0};
    
    wchar_t userarg[256];
    MultiByteToWideChar(CP_ACP, 0, argv[1], -1, userarg, 256);
    
    wchar_t* sep = wcschr(userarg, L'\\');
    if (sep) {
        size_t domlen = sep - userarg;
        wcsncpy(domain, userarg, domlen);
        domain[domlen] = L'\0';
        wcscpy(username, sep + 1);
    } else {
        wcscpy(username, userarg);
    }
    
    MultiByteToWideChar(CP_ACP, 0, argv[2], -1, password, 256);
    MultiByteToWideChar(CP_ACP, 0, argv[3], -1, cmdline, 4096);
    for (int i = 4; i < argc; i++) {
        wcscat(cmdline, L" ");
        wchar_t tmp[512];
        MultiByteToWideChar(CP_ACP, 0, argv[i], -1, tmp, 512);
        wcscat(cmdline, tmp);
    }
    
    printf("=== RunAsEx ===\n");
    printf("[*] Target: %ls\\%ls\n", domain, username);
    printf("[*] Comando: %ls\n\n", cmdline);
    
    BOOL hasImpersonate = HasPrivilege(SE_IMPERSONATE_NAME_W);
    BOOL hasAssignToken = HasPrivilege(SE_ASSIGNPRIMARYTOKEN_NAME_W);
    
    printf("[*] SeImpersonatePrivilege:        %s\n", hasImpersonate ? "SI" : "NO");
    printf("[*] SeAssignPrimaryTokenPrivilege: %s\n\n", hasAssignToken ? "SI" : "NO");
    
    if (hasImpersonate) EnablePrivilege(SE_IMPERSONATE_NAME_W);
    if (hasAssignToken) EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME_W);
    
    PROCESS_INFORMATION pi = {0};
    BOOL success = FALSE;
    
    // Prova tutti i tipi di logon
    if (!success)
        success = TryLogonAndRun(username, domain, password, cmdline, 
                                  LOGON32_LOGON_INTERACTIVE, "INTERACTIVE", &pi);
    if (!success)
        success = TryLogonAndRun(username, domain, password, cmdline, 
                                  LOGON32_LOGON_BATCH, "BATCH", &pi);
    if (!success)
        success = TryLogonAndRun(username, domain, password, cmdline, 
                                  LOGON32_LOGON_SERVICE, "SERVICE", &pi);
    if (!success)
        success = TryLogonAndRun(username, domain, password, cmdline, 
                                  LOGON32_LOGON_NEW_CREDENTIALS, "NEW_CREDENTIALS", &pi);
    if (!success)
        success = TryWithLogonW(username, domain, password, cmdline, &pi);
    
    if (success) {
        printf("\n[+] PID: %lu\n", pi.dwProcessId);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("\n[-] Tutti i metodi falliti.\n");
        return 1;
    }
    
    SecureZeroMemory(password, sizeof(password));
    return 0;
}
