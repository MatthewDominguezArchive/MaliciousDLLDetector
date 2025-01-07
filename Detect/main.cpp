#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <TlHelp32.h>
#include <psapi.h>
#include <unordered_set>
#include <sstream>
#include <iomanip>
#include <array>
#include <fstream>

std::string FileToSHA256(const std::string& filePath) {
    constexpr size_t BlockSize = 64;
    constexpr std::array<uint32_t, 64> k{
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    auto rightRotate = [](uint32_t value, unsigned int count) {
        return (value >> count) | (value << (32 - count));
        };

    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        return "";
    }

    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(fileSize);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), fileSize)) {
        return "";
    }

    std::array<uint32_t, 8> hash{
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    uint8_t tempBuffer[BlockSize]{};
    size_t bufferLength = 0;
    uint64_t totalBits = 0;

    auto processBlock = [&](const uint8_t* block) {
        uint32_t w[64]{};
        for (size_t i = 0; i < 16; ++i) {
            w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
        }
        for (size_t i = 16; i < 64; ++i) {
            uint32_t s0 = rightRotate(w[i - 15], 7) ^ rightRotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rightRotate(w[i - 2], 17) ^ rightRotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = hash[0];
        uint32_t b = hash[1];
        uint32_t c = hash[2];
        uint32_t d = hash[3];
        uint32_t e = hash[4];
        uint32_t f = hash[5];
        uint32_t g = hash[6];
        uint32_t h = hash[7];

        for (size_t i = 0; i < 64; ++i) {
            uint32_t S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + k[i] + w[i];
            uint32_t S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
        };

    size_t i = 0;
    while (i + BlockSize <= buffer.size()) {
        processBlock(&buffer[i]);
        i += BlockSize;
    }

    bufferLength = buffer.size() - i;
    std::copy(&buffer[i], &buffer[i] + bufferLength, tempBuffer);

    tempBuffer[bufferLength++] = 0x80;
    if (bufferLength > BlockSize - 8) {
        std::fill(tempBuffer + bufferLength, tempBuffer + BlockSize, 0);
        processBlock(tempBuffer);
        bufferLength = 0;
    }

    std::fill(tempBuffer + bufferLength, tempBuffer + BlockSize - 8, 0);
    totalBits = buffer.size() * 8;
    for (int j = 7; j >= 0; --j) {
        tempBuffer[BlockSize - 8 + j] = totalBits & 0xFF;
        totalBits >>= 8;
    }
    processBlock(tempBuffer);

    std::ostringstream oss;
    for (uint32_t h : hash) {
        oss << std::hex << std::setw(8) << std::setfill('0') << h;
    }
    return oss.str();
}

HANDLE GetProcessHandle(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 process;
    process.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &process)) {
        return 0;
    }

    while (Process32Next(hSnapshot, &process)) {
        if (!_stricmp(process.szExeFile, processName)) {
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process.th32ProcessID);
            CloseHandle(hSnapshot);
            return hProcess;
        }
    }

    CloseHandle(hSnapshot);
    return 0;
}

std::unordered_set<std::string>validDLLPaths = { "C:\\Windows\\SYSTEM32\\ntdll.dll",
"C:\\Windows\\System32\\KERNEL32.DLL", "C:\\Windows\\System32\\KERNELBASE.dll",
"C:\\Windows\\System32\\GDI32.dll", "C:\\Windows\\System32\\win32u.dll", "C:\\Windows\\System32\\gdi32full.dll",
"C:\\Windows\\System32\\msvcp_win.dll", "C:\\Windows\\System32\\ucrtbase.dll", "C:\\Windows\\System32\\USER32.dll",
"C:\\Windows\\System32\\combase.dll","C:\\Windows\\System32\\RPCRT4.dll", "C:\\Windows\\System32\\shcore.dll", "C:\\Windows\\System32\\msvcrt.dll",
"C:\\Windows\\WinSxS\\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.19041.4355_none_60b8b9eb71f62e16\\COMCTL32.dll",
"C:\\Windows\\System32\\IMM32.DLL", "C:\\Windows\\System32\\bcryptPrimitives.dll", "C:\\Windows\\System32\\ADVAPI32.dll",
"C:\\Windows\\System32\\sechost.dll", "C:\\Windows\\System32\\bcrypt.dll", "C:\\Windows\\SYSTEM32\\kernel.appcore.dll",
"C:\\Windows\\system32\\uxtheme.dll", "C:\\Windows\\System32\\clbcatq.dll", "C:\\Windows\\System32\\MrmCoreR.dll",
"C:\\Windows\\System32\\SHELL32.dll", "C:\\Windows\\SYSTEM32\\windows.storage.dll", "C:\\Windows\\system32\\Wldp.dll",
"C:\\Windows\\System32\\OLEAUT32.dll", "C:\\Windows\\System32\\shlwapi.dll", "C:\\Windows\\System32\\MSCTF.dll",
"C:\\Windows\\system32\\TextShaping.dll", "C:\\Windows\\System32\\efswrt.dll", "C:\\Windows\\SYSTEM32\\wintypes.dll",
"C:\\Windows\\System32\\MPR.dll", "C:\\Windows\\System32\\twinapi.appcore.dll", "C:\\Windows\\System32\\oleacc.dll",
"C:\\Windows\\SYSTEM32\\textinputframework.dll", "C:\\Windows\\System32\\CoreMessaging.dll", "C:\\Windows\\System32\\WS2_32.dll",
"C:\\Windows\\System32\\CoreUIComponents.dll", "C:\\Windows\\SYSTEM32\\ntmarta.dll", "C:\\Windows\\system32\\notepad.exe" };

std::unordered_set<std::string> validDLLHashes = {
    "59a0fc73540e071d80ced04135ce59b8350453a1ace94ee465a439df996cf63b",
    "b8782a715a51518046020183bc55aedef913b438c1229f5506bbfd3ea9039850",
    "a2e4ca9c9c43d94d297031cc5fb6504512a29c7f9b84493b3be270b74525ec5c",
    "123a49174b44b2b9b80f42cb624d2acdf2ad517e1bb16a381f59879dc9e33bcd",
    "84b693a8f8838446169455b403f8cb75af0d89befb7bcf9be22405b6c9df4695",
    "2a7825c2925347e0cb767a0dcb611f3eb80d0f71cbec981069b227bdc7cb871a",
    "e12f1cff7976d44c4919a3d5a3471aa7a996ef00c193a5396b31e32fafeda606",
    "6b71520f37e7e30934966fbab9b60de6f194703b6a246a6272feeb1c37e1930e",
    "3e9f77910432348b6beff52f2204a934880ea2bbe9ca31c3c585d1332c3b3106",
    "a7f4196d9476d36894ce17c3b0dd97504ca2cc31b3e0a774fee326e867565885",
    "342c52bd4383da3a8d66bd01c306479ec15b9bb3088a123ac78f555a7c2101f9",
    "de60bf11a8d3102a895535fdd843884ab244bbeeb0db09a819e5abfa39025d50",
    "f0a1662d0f55533a21d609f8dc737288ede77d314d90e885ca9e6ef79d429c3b",
    "bcc9fbc74fa1312362ab08c191f5d673f097ec80f84c041ce8b901b040cbea3b",
    "6023e5e4759ad1abb0ad479cd6829e7e8ccc17be5af7764561ac0f845374091f",
    "5d05db7db46d509ff71b7a952fd36d3a9e432f1e8e26fa0a5772f3d260146e81",
    "abff38d9efaca07602acc2a31775f8790ac720261842dbb6d7d9e1a46bba91f8",
    "af30c5fddaf675df238f0da108843367b1075fe691a76b6642bf8595b62860cf",
    "dcf366d2ea852ed55580e6d406f353f2b6884b99432e6fe160231298ebacd669",
    "881469d3e8f55810f34ddd3040827ba833f307dbe97cbac93fb1d9c3e64cc90d",
    "4b861ae81345f2d950ad34f5bfbfad949fad0501a3b38cd2c334ffa1c0affc8d",
    "ecca6c5f7c8f7778baa104c65b3656ffe225a8aa47c9f2e3ebd507f2486efa11",
    "4dd40579e7254dd553b49b229aa85b9c079586b034e37e564909da25eb298345",
    "14e21a2f7da1a70323de21fdb8cce27b3af9abde453ae88809d05cc2357e1e64",
    "73bf398664b4611890b40e314ce10c367222ef20597b6324fc3f6ee73c793c4e",
    "8f55d262f4bc66d5d75d0202f21470f37e7a8369cedb25e916ce26e99cc433ca",
    "dca8bd6641930d4f805bafb5235ac194df83b0a48b8d76fada111ff3ad119cf7",
    "c88767385db737683142ef952a595ca9d882bafc6fb1d327651bee8fa0acc55b",
    "87b284208599017965feea91e803255d9844f85128d315694878f548bfb39834",
    "de8bca700cac6780a46a999fe326615b320ff05d45dfd47cf42306685a8ad0dc",
    "7022a351184a3abae666c5c6c74bfc13445f85cfd938543a1395307e8d4441f3",
    "5e9857a80a301ad21d0e0a0928a4ff2b5360c305a97bfc88886e3b686bf8d503",
    "fae19e51c442e1a4c181cc4391e985180bf683653906af1cf74a06276862c568",
    "252d198d0660d7d021209c25ed91333a63ccb00e47b00521af9cb562ca1d7e3a",
    "c286747d319818c1205fd487040840353c5f4542faffdabae9131481bdfeb92a",
    "0342ed124ee25c76b6b6284f2c4dc3bede90c18c1122c36ec2424a8f5332c3ba",
    "3c60056371f82e4744185b6f2fa0c69042b1e78804685944132974dd13f3b6d9",
    "8dbc0e66b480969ab6b9a802105376b4eb18481502bcea7caddc87bf3e707c33",
    "d1ff2c49e692cce061d33b43798aa909c14cc86a549a5da27fe87fdf40129d3c",
    "c6371199e4ffc724cd6dff276cab4cc57bd0099fd2bf2e1348bf817aa8c28bcb",
    "eae80a9aaeaa3cf42a5fb81c2e188ee22b3da5a48a6be779d6d899c5adc85ee9"
};

std::vector<std::string> GetLoadedDLLs(HANDLE processHandle) {
    std::vector<std::string> dllList;
    HMODULE modules[1024];
    DWORD bytesNeeded;

    if (!EnumProcessModulesEx(processHandle, modules, sizeof(modules), &bytesNeeded, LIST_MODULES_ALL)) {
        return {};
    }

    size_t moduleCount = bytesNeeded / sizeof(HMODULE);

    for (size_t i = 0; i < moduleCount; ++i) {
        wchar_t moduleName[MAX_PATH];

        if (!GetModuleFileNameExW(processHandle, modules[i], moduleName, sizeof(moduleName) / sizeof(wchar_t))) {
            std::cout << "Failed To Get File" << std::endl;
            continue;
        }

        char moduleNameStr[MAX_PATH];

        if (WideCharToMultiByte(CP_UTF8, 0, moduleName, -1, moduleNameStr, MAX_PATH, NULL, NULL)) {
            dllList.push_back(moduleNameStr);
        }
    }

    return dllList;
}


int main() {
    HANDLE notepadHandle = GetProcessHandle("notepad.exe");
    if (!notepadHandle) {
        return 1;
    }
    while (true) {
        for (std::string dll : GetLoadedDLLs(notepadHandle)) {
            if (validDLLPaths.find(dll) == validDLLPaths.end()) {
                std::cout << "Invalid: " << dll << std::endl;
            }
            if (validDLLHashes.find(FileToSHA256(dll)) == validDLLHashes.end()) {
                std::cout << "Invalid: " << FileToSHA256(dll) << std::endl;
            }
        }
    }

    return 0;
}