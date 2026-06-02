#pragma once
#include <vector>
#include <string>
#include <windows.h>

std::vector<BYTE> DownloadAndDecryptShellcode(std::string url, std::string cle_hex, std::string iv_hex);
