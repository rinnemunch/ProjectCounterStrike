#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <psapi.h>
#include <tchar.h> 
#include <string> 
#include <comdef.h>
#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib") 
#include <fstream>
#include <ctime>



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

void logDetection(const std::wstring& scriptName, DWORD pid); 
void killProcessByPid(DWORD pid);

bool isKeyloggerScriptRunning(const std::wstring& scriptName) {
    HRESULT hres;

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return false;

    hres = CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) {
        CoUninitialize();
        return false;
    }

    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        CoUninitialize();
        return false;
    }

    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    hres = CoSetProxyBlanket(pSvc,
        RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE);

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT CommandLine, ProcessId FROM Win32_Process WHERE Name = 'python.exe'"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL, &pEnumerator);

    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) break;

        VARIANT vtCmd, vtPid;
        VariantInit(&vtCmd);
        VariantInit(&vtPid);

        hr = pclsObj->Get(L"CommandLine", 0, &vtCmd, 0, 0);
        hr = pclsObj->Get(L"ProcessId", 0, &vtPid, 0, 0);

        if (SUCCEEDED(hr) && vtCmd.vt == VT_BSTR && vtPid.vt == VT_I4) {
            std::wstring cmdLine(vtCmd.bstrVal);
            DWORD pid = vtPid.intVal;

            if (cmdLine.find(scriptName) != std::wstring::npos) {
                std::wcout << L"[+] Found script in cmdline: " << cmdLine << std::endl;

                logDetection(scriptName, pid); 
                killProcessByPid(pid);

                VariantClear(&vtCmd); 
                VariantClear(&vtPid);
                pclsObj->Release();
                pEnumerator->Release();
                pSvc->Release();
                pLoc->Release();
                CoUninitialize();
                return true;
            }
        }

        VariantClear(&vtPid);
        pclsObj->Release();
    }

    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    return false;
}

void logDetection(const std::wstring& scriptName, DWORD pid) {
    std::ofstream logFile("detection_log.txt", std::ios::app);

    // current time
    std::time_t now = std::time(nullptr);
    char timeStr[100];
    std::strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

    // log entry
    logFile << "[" << timeStr << "] Detected "
        << std::string(scriptName.begin(), scriptName.end())
        << " (PID: " << pid << ")\n";

    logFile.close();
}

void killProcessByPid(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess != NULL) {
        if (TerminateProcess(hProcess, 0)) {
            std::wcout << L"Successfully killed process (PID: " << pid << L")" << std::endl;
        }
        else {
            std::wcout << L"Failed to kill process (PID: " << pid << L")" << std::endl;
        }
        CloseHandle(hProcess);
    }
    else {
        std::wcout << L"Could not open process for termination (PID: " << pid << L")" << std::endl;
    }
}

int main() {
    isKeyloggerScriptRunning(L"keylogger.py");
    return 0;
}



