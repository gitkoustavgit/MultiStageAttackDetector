$word = New-Object -ComObject Word.Application
$word.Visible = $false
$docPath = "C:\Users\Srikar Bharadwaj\Desktop\Projects\Context-Aware AI Detection of Multi-Stage Injection Attacks\Final_Template.docx"
$pdfPath = "C:\Users\Srikar Bharadwaj\Desktop\Projects\Context-Aware AI Detection of Multi-Stage Injection Attacks\Final_Template.pdf"

try {
    $doc = $word.Documents.Open($docPath)
    $pages = $doc.ComputeStatistics(2)
    Write-Host "Total Page Count: $pages"
    $doc.SaveAs([ref]$pdfPath, [ref]17)
    Write-Host "PDF Exported successfully: $pdfPath"
    
    Write-Host "=== HEADING PAGE NUMBERS ==="
    foreach ($para in $doc.Paragraphs) {
        $text = $para.Range.Text.Trim()
        if ($text -match '^[1-9]\.\s+[A-Z]' -or $text -match '^[1-9]\.[0-9]' -or $text -eq 'ABSTRACT' -or $text -eq 'DECLARATION' -or $text -eq 'CERTIFICATE' -or $text -eq 'ACKNOWLEDGEMENTS' -or $text -eq 'TABLE OF CONTENTS' -or $text -eq 'List of Figures' -or $text -eq 'List of Tables' -or $text -eq 'List of Abbreviations' -or $text -eq 'Symbols and Notations') {
            $pAbs = $para.Range.Information(3) # wdActiveEndPageNumber
            $pAdj = $para.Range.Information(1) # wdActiveEndAdjustedPageNumber
            Write-Host "Page $pAdj [Abs $pAbs] : $text"
        }
    }
    
    $doc.Close([ref]$false)
}
finally {
    $word.Quit()
}
