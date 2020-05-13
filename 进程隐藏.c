typedef NTSTATUS (WINAPI* pfnNtQueryInformationProcess)(
  IN HANDLE           ProcessHandle,	
  IN PROCESSINFOCLASS ProcessInformationClass,	
  OUT PVOID           ProcessInformation,	
  IN ULONG            ProcessInformationLength,
  OUT PULONG          ReturnLength
 );
BOOL DisguiseProcess(DWORD dwProcessId, WCHAR* lpwszpath, WCHAR* lpwszCmd)
{
    //获取进程句柄
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (!hProcess)
	{
		OutPutDebugStringA("进程句柄获取失败\n");
		return false;
	}
    //
    pfnNtQueryInformationProcess fnNtQueryInformationProcess = NULL;
    
}
