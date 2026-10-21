$word = New-Object -ComObject Word.Application
$word.Visible = $false
try {
    $doc = $word.Documents.Open("C:\Users\Srikar Bharadwaj\Desktop\Projects\Context-Aware AI Detection of Multi-Stage Injection Attacks\Final_Template.docx")
    foreach ($para in $doc.Paragraphs) {
        $txt = $para.Range.Text.Trim()
        if ($txt -match '^Fig\.\s*[0-9]+' -or $txt -match '^Table\s*[0-9]+') {
            $pAbs = $para.Range.Information(3)
            $pAdj = $para.Range.Information(1)
            Write-Host "Page ${pAdj} [Abs ${pAbs}] : ${txt}"
        }
    }
    $doc.Close([ref]$false)
} finally {
    $word.Quit()
}
