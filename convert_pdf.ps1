$word = New-Object -ComObject Word.Application
$word.Visible = $false
$docPath = "C:\Users\Srikar Bharadwaj\Desktop\Projects\Context-Aware AI Detection of Multi-Stage Injection Attacks\BCSE497J Project I Report.docx"
$pdfPath = "C:\Users\Srikar Bharadwaj\Desktop\Projects\Context-Aware AI Detection of Multi-Stage Injection Attacks\BCSE497J Project I Report.pdf"

try {
    $doc = $word.Documents.Open($docPath)
    $pages = $doc.ComputeStatistics(2)
    Write-Host "Page Count: $pages"
    $doc.SaveAs([ref]$pdfPath, [ref]17)
    Write-Host "PDF Exported successfully: $pdfPath"
    
    # Let's inspect page numbers of key headings
    Write-Host "Finding heading page numbers..."
    foreach ($para in $doc.Paragraphs) {
        $text = $para.Range.Text.Trim()
        if ($text -match '^[1-9]\.\s+[A-Z]' -or $text -match '^[1-9]\.[0-9]' -or $text -eq 'Abstract' -or $text -eq 'Table of Contents') {
            $pageNum = $para.Range.Information(3) # 3 = wdActiveEndPageNumber
            Write-Host "$pageNum : $text"
        }
    }
    
    $doc.Close([ref]$false)
}
finally {
    $word.Quit()
}
