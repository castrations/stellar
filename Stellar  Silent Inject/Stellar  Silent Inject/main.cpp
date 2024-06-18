#include <iostream>
#include <fstream>
#include <Windows.h>
#include <TlHelp32.h>
#include <Shlwapi.h>
#include <string>
#include <chrono>
#include <thread>

#pragma comment(lib, "shlwapi.lib")

#define CONFIG_FILE L"config.txt"
#define print(format, ...) fprintf(stderr, format, __VA_ARGS__)

// Functions
DWORD GetProcId(const wchar_t* pn, unsigned short int fi = 0b1101);
bool TerminateExistingInstance(const wchar_t* exeName);

bool TerminateExistingInstance(const wchar_t* exeName)
{
    DWORD procId = GetProcId(exeName);
    if (procId != 0)
    {
        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, procId);
        if (hProc != NULL)
        {
            TerminateProcess(hProc, 0);
            CloseHandle(hProc);
            return true;
        }
    }
    return false;
}

void StartProcess(const wchar_t* processPath)
{
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!CreateProcessW(NULL, (LPWSTR)processPath, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        std::cerr << "Failed to start process: " << GetLastError() << std::endl;
    }
    else
    {
        // watermark!
        std::wcout << L"  _     _       ____  _                _  __      ____   ___  \n"
            << L" | |   | |     |___ \\| |              | |/ _|    |___ \\ / _ \\ \n"
            << L" | |__ | |_ ___  __) | |_ __ _ ___  __| | |___  __ __) | | | |\n"
            << L" | '_ \\| __/ __||__ <| __/ _` / __|/ _` |  _\\ \\/ /|__ <| | | |\n"
            << L" | |_) | || (__ ___) | || (_| \\__ \\ (_| | |  >  < ___) | |_| |\n"
            << L" |_.__/ \\__\\___|____/ \\__\\__,_|___/\\__,_|_| /_/\\_\\____/ \\___/ \n"
            << L"                                                              \n"
            << L"                                                              \n";

        std::wcout << L"Started Stellar: " << processPath << L" with PID: " << pi.dwProcessId << std::endl;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

DWORD GetProcId(const wchar_t* pn, unsigned short int fi)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W pE;
        pE.dwSize = sizeof(pE);

        if (Process32FirstW(hSnap, &pE))
        {
            if (!pE.th32ProcessID)
                Process32NextW(hSnap, &pE);
            do
            {
                if (fi == 0b10100111001)
                    std::wcout << pE.szExeFile << L"\t\t" << pE.th32ProcessID << std::endl;
                if (!_wcsicmp(pE.szExeFile, pn))
                {
                    procId = pE.th32ProcessID;
                    print("Process ID: 0x%lX\n", procId);
                    break;
                }
            } while (Process32NextW(hSnap, &pE));
        }
    }
    CloseHandle(hSnap);
    return procId;
}

BOOL InjectDLL(DWORD procID, const wchar_t* dllPath)
{
    BOOL WPM = 0;

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procID);
    if (hProc == NULL)
    {
        print("Failed to open target process: %d\n", GetLastError());
        return FALSE;
    }

    void* loc = VirtualAllocEx(hProc, 0, (wcslen(dllPath) + 1) * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (loc == NULL)
    {
        print("Failed to allocate memory in target process: %d\n", GetLastError());
        CloseHandle(hProc);
        return FALSE;
    }

    WPM = WriteProcessMemory(hProc, loc, dllPath, (wcslen(dllPath) + 1) * sizeof(wchar_t), NULL);
    if (!WPM)
    {
        print("Failed to write memory in target process: %d\n", GetLastError());
        VirtualFreeEx(hProc, loc, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }
    print("DLL path written successfully to target process memory.\n");

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, loc, 0, NULL);
    if (hThread == NULL)
    {
        print("Failed to create remote thread in target process: %d\n", GetLastError());
        VirtualFreeEx(hProc, loc, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }
    print("Remote thread created successfully.\n");

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProc, loc, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return TRUE;
}

void SaveConfig(const std::wstring& processName, const std::wstring& dllPath, const std::wstring& exePath)
{
    std::wofstream config(CONFIG_FILE);
    if (config.is_open())
    {
        config << processName << std::endl;
        config << dllPath << std::endl;
        config << exePath << std::endl;
        config.close();
    }
}

bool LoadConfig(std::wstring& processName, std::wstring& dllPath, std::wstring& exePath)
{
    std::wifstream config(CONFIG_FILE);
    if (config.is_open())
    {
        std::getline(config, processName);
        std::getline(config, dllPath);
        std::getline(config, exePath);
        config.close();
        return true;
    }
    return false;
}

int wmain(void)
{
    std::wstring pname, dllpath, exepath;

    if (!LoadConfig(pname, dllpath, exepath))
    {
        std::wcout << L"Process name (Taskmgr.exe): ";
        std::wcin >> pname;
        std::wcout << L"DLL path (Full path to the desired DLL): ";
        std::wcin >> dllpath;
        std::wcout << L"Stellar path (Full path to Stellar): ";
        std::wcin >> exepath;
        SaveConfig(pname, dllpath, exepath);
    }
    else
    {
        std::wcout << L"Using saved configuration:\n";
        std::wcout << L"Stellar name: " << pname << std::endl;
        std::wcout << L"DLL path: " << dllpath << std::endl;
        std::wcout << L"Stellar path: " << exepath << std::endl;
    }

    system("cls");

    if (PathFileExistsW(dllpath.c_str()) == FALSE)
    {
        print("DLL File does NOT exist!");
        return EXIT_FAILURE;
    }

    if (PathFileExistsW(exepath.c_str()) == FALSE)
    {
        print("Executable File does NOT exist!");
        return EXIT_FAILURE;
    }

    // Start stellar as a hidden process
    StartProcess(exepath.c_str());
    Sleep(5000);

    // Let the Stellar load
    std::wcout << L"Letting Stellar load." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(10));

    DWORD procId = 0;
    procId = GetProcId(pname.c_str());
    if (procId == 0)
    {
        print("Process Not found (0x%lX)\n", GetLastError());
        print("Here is a list of available processes:\n");
        Sleep(3500);
        system("cls");
        GetProcId(L"skinjbir", 0b10100111001);
    }
    else
    {
        if (!InjectDLL(procId, dllpath.c_str()))
        {
            print("DLL Injection failed (0x%lX)\n", GetLastError());
        }
    }

    // Adding a short delay before exiting
    std::this_thread::sleep_for(std::chrono::seconds(2));

    return EXIT_SUCCESS;
}
