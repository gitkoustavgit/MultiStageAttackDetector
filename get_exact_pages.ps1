$word = New-Object -ComObject Word.Application
$word.Visible = $false
$docPath = "C:\Users\Srikar Bharadwaj\Desktop\Projects\Context-Aware AI Detection of Multi-Stage Injection Attacks\Final_Template.docx"

try {
    $doc = $word.Documents.Open($docPath)
    Write-Host "=== PRINTING ADJUSTED AND ABSOLUTE PAGE NUMBERS ==="
    foreach ($para in $doc.Paragraphs) {
        $txt = $para.Range.Text.Trim()
        if ($txt -match '^[1-9]\.\s+[A-Z]' -or $txt -match '^[1-9]\.[0-9]' -or $txt -eq 'ABSTRACT' -or $txt -eq 'TABLE OF CONTENTS' -or $txt -eq 'List of Figures' -or $txt -eq 'List of Tables' -or $txt -eq 'List of Abbreviations' -or $txt -eq 'Symbols and Notations') {
            $pAbs = $para.Range.Information(3) # wdActiveEndPageNumber
            $pAdj = $para.Range.Information(1) # wdActiveEndAdjustedPageNumber
            Write-Host "Page $pAdj [Abs $pAbs] : $txt"
        }
    }
    $doc.Close([ref]$false)
}
finally {
    $word.Quit()
}
