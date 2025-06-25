#include <windows.h>
#include <tlhelp32.h>
#include <iostream>


#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

bool isPythonRunning() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"python.exe") == 0) {
                std::wcout << L"[!] Found python.exe — PID: " << pe.th32ProcessID << std::endl;
                CloseHandle(hSnapshot);
                return true;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return false;
}

int main() {
    if (isPythonRunning()) {
        std::cout << "Python process detected!" << std::endl;
    }
    else {
        std::cout << "No Python keylogger running." << std::endl;
    }

    return 0;
}

