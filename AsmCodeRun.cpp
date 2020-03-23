#include "AsmCodeRun.h"
#include <qmessagebox.h>

//hex -> asm
#include "capstone/include/capstone.h"
#include "capstone/include/platform.h"

//asm -> hex
#include "keystone/include/keystone.h"


#ifdef _WIN64

#ifdef _DEBUG
#pragma comment(lib,"capstone/64lib/capstoned.lib")
#pragma comment(lib,"keystone/64lib/keystoned.lib")
#else
#pragma comment(lib,"capstone/64lib/capstone.lib")
#pragma comment(lib,"keystone/64lib/keystone.lib")
#endif

#else
#ifdef _DEBUG
#pragma comment(lib,"capstone/32lib/capstoned.lib")
#pragma comment(lib,"keystone/32lib/keystoned.lib")
#else
#pragma comment(lib,"capstone/32lib/capstone.lib")
#pragma comment(lib,"keystone/32lib/keystone.lib")
#endif
#endif

AsmCodeRun::AsmCodeRun(QWidget* parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);

    m_pHexBuffer = nullptr;
    m_nHexBufferLength = 0;

    QIntValidator v(0, 65536, this);
    ui.ProcessID->setValidator(&v);
    GrantPriviledge(SE_DEBUG_NAME);
    connect(ui.ExchangeCode, SIGNAL(clicked()), this, SLOT(ExchangeCodeClicked()));
    connect(ui.RunCode, SIGNAL(clicked()), this, SLOT(RunCodeClicked()));
}

bool AsmCodeRun::ExchangeCodeClicked()
{
    QString qsAsmCode = ui.AsmCode->toPlainText();

    if (PraseAsm(qsAsmCode) == false)
    {
        QMessageBox::about(this, "Error", "Asm Format Error");
        return false;
    }
    return true;
}

bool AsmCodeRun::RunCodeClicked()
{
    if (ui.ProcessID->text().length() <= 0)
    {
        QMessageBox::about(this, "Error", "Process ID Is Empty");
        return false;
    }

    if (ExchangeCodeClicked() == false)
    {
        QMessageBox::about(this, "Error", "Asm Format Error");
        return false;
    }

    if (m_pHexBuffer == nullptr)
    {
        QMessageBox::about(this, "Error", "Prase Asm Code Error");
        return false;
    }

    if (RunShellCode() == false)
    {
        QMessageBox::about(this, "Error", "Asm Code Cann't Run");
        return false;
    }
    else
    {
        QMessageBox::information(this, "Success", "Asm Code Running");
        return true;
    }

}

bool AsmCodeRun::PraseAsm(QString qsAsmCode)
{
    bool bRet = false;
    ks_engine* ks = nullptr;
    ks_err err = KS_ERR_OK;
    size_t count = 0;
    unsigned char* encode = nullptr;
    size_t size = 0;
    int error = 0;

#ifdef _WIN64
    err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
#else
    err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
#endif // _WIN32

    if (err != KS_ERR_OK) {
        printf("ERROR: failed on ks_open(), quit\n");
        return false;
    }

    qsAsmCode.toUpper();
    std::string str = qsAsmCode.toStdString();
    const char* pCode = str.c_str();

#ifdef _WIN64
    error = ks_asm(ks, pCode, 0x0140000000, &encode, &size, &count);
#else
    error = ks_asm(ks, pCode, 0x00401000, &encode, &size, &count);
#endif
    if (error != KS_ERR_OK) {
        bRet = false;
    }
    else {

        if (m_pHexBuffer)
        {
            delete[] m_pHexBuffer;
            m_pHexBuffer = nullptr;
            m_nHexBufferLength = 0;
        }

        m_pHexBuffer = new unsigned char[size];
        if (m_pHexBuffer == nullptr)
        {
            bRet = false;
        }
        else
        {
            size_t i = 0;
            int nPos = 0;
            memset(m_pHexBuffer, 0, size);
            memcpy(m_pHexBuffer, encode, size);

            m_nHexBufferLength = size;

            QString qsHex;

            for (i = 0; i < size; i++) {
                char szHex[4] = { 0 };
                sprintf_s(szHex, 4, "%02X ", m_pHexBuffer[i]);
                qsHex.append(szHex);
            }

            ui.ReturnCode->setText(qsHex);
            bRet = true;
        }
    }

    // NOTE: free encode after usage to avoid leaking memory
    ks_free(encode);

    // close Keystone instance when done
    ks_close(ks);

    return bRet;
}

bool AsmCodeRun::RunShellCode()
{
    int ProcessId = ui.ProcessID->text().toInt();

    //获线程IdVector
    vector<unsigned int>	ThreadIdVector;
    GetThreadIdByProcessId(ProcessId, ThreadIdVector);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
    if (hProcess == NULL)
    {
        QMessageBox::about(this, "Error", "OpenProcess Error");
        return false;
    }

    LPVOID lpAllocAddr = VirtualAllocEx(hProcess, NULL, m_nHexBufferLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (lpAllocAddr == NULL)
    {
        CloseHandle(hProcess);
        QMessageBox::about(this, "Error", "VirtualAllocEx Error");
        return false;
    }

    SIZE_T dwWrited = 0;
    DWORD bRet = WriteProcessMemory(hProcess, lpAllocAddr, m_pHexBuffer, m_nHexBufferLength, &dwWrited);

    if (bRet == 0 || dwWrited != m_nHexBufferLength)
    {
        VirtualFreeEx(hProcess, lpAllocAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        QMessageBox::about(this, "Error", "WriteProcessMemory Error");
        return false;
    }

    VirtualProtectEx(hProcess, lpAllocAddr, m_nHexBufferLength, PAGE_EXECUTE_READ, &bRet);

    HANDLE hRemoteThread = ::CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpAllocAddr, NULL, 0, NULL, NULL);
    if (hRemoteThread == NULL)
    {
        VirtualFreeEx(hProcess, lpAllocAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        QMessageBox::about(this, "Error", "CreateRemoteThreadEx Error");
    }
    CloseHandle(hRemoteThread);
    CloseHandle(hProcess);
    return true;
}

bool AsmCodeRun::GetThreadIdByProcessId(int ProcessId, vector<unsigned int>& ThreadIdVector)
{
    HANDLE			ThreadSnapshotHandle = NULL;
    THREADENTRY32	ThreadEntry32 = { 0 };

    ThreadEntry32.dwSize = sizeof(THREADENTRY32);

    ThreadSnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);		// 给系统所有的线程快照
    if (ThreadSnapshotHandle == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    if (Thread32First(ThreadSnapshotHandle, &ThreadEntry32))
    {
        do
        {
            if (ThreadEntry32.th32OwnerProcessID == ProcessId)
            {
                ThreadIdVector.emplace_back(ThreadEntry32.th32ThreadID);		// 把该进程的所有线程id压入模板
            }
        } while (Thread32Next(ThreadSnapshotHandle, &ThreadEntry32));
    }

    CloseHandle(ThreadSnapshotHandle);
    ThreadSnapshotHandle = NULL;
    return TRUE;
}

bool AsmCodeRun::InjectDllByApc(LPVOID Address, unsigned int ThreadId)
{

    try
    {
        HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, ThreadId);
        if (hThread)
        {
            QueueUserAPC((PAPCFUNC)Address, hThread, NULL);
            CloseHandle(hThread);
        }
    }
    catch (...)
    {
        return false;
    }
    return true;
}

bool AsmCodeRun::GrantPriviledge(IN PWCHAR PriviledgeName)
{
    TOKEN_PRIVILEGES TokenPrivileges, OldPrivileges;
    DWORD			 dwReturnLength = sizeof(OldPrivileges);
    HANDLE			 TokenHandle = NULL;
    LUID			 uID;

    // 打开权限令牌
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &TokenHandle))
    {
        if (GetLastError() != ERROR_NO_TOKEN)
        {
            return FALSE;
        }
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle))
        {
            return FALSE;
        }
    }

    if (!LookupPrivilegeValue(NULL, PriviledgeName, &uID))		// 通过权限名称查找uID
    {
        CloseHandle(TokenHandle);
        TokenHandle = NULL;
        return FALSE;
    }

    TokenPrivileges.PrivilegeCount = 1;		// 要提升的权限个数
    TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;    // 动态数组，数组大小根据Count的数目
    TokenPrivileges.Privileges[0].Luid = uID;

    // 在这里我们进行调整权限
    if (!AdjustTokenPrivileges(TokenHandle, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), &OldPrivileges, &dwReturnLength))
    {
        CloseHandle(TokenHandle);
        TokenHandle = NULL;
        return FALSE;
    }

    // 成功了
    CloseHandle(TokenHandle);
    TokenHandle = NULL;

    return TRUE;
}