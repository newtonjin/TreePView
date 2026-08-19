# Draws the source icon for the Tauri bundler.
#
# Generated rather than committed as a binary so the shape stays reviewable in
# the repository, and so the palette cannot drift from the one in styles.css.
# Run this, then `npm run tauri icon icons/source.png` to produce the platform
# icon set.

Add-Type -AssemblyName System.Drawing

$S = 1024
$bmp = New-Object System.Drawing.Bitmap($S, $S)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = 'AntiAlias'

$bg      = [System.Drawing.Color]::FromArgb(255, 13, 17, 23)
$accent  = [System.Drawing.Color]::FromArgb(255, 76, 154, 255)
$edge    = [System.Drawing.Color]::FromArgb(255, 45, 86, 138)
$alert   = [System.Drawing.Color]::FromArgb(255, 255, 77, 94)
$rail    = [System.Drawing.Color]::FromArgb(255, 34, 44, 56)

# Rounded background.
$r = 180
$path = New-Object System.Drawing.Drawing2D.GraphicsPath
$path.AddArc(0, 0, $r, $r, 180, 90)
$path.AddArc($S - $r, 0, $r, $r, 270, 90)
$path.AddArc($S - $r, $S - $r, $r, $r, 0, 90)
$path.AddArc(0, $S - $r, $r, $r, 90, 90)
$path.CloseFigure()
$g.FillPath((New-Object System.Drawing.SolidBrush($bg)), $path)

# Timeline rail along the bottom, with density ticks.
$railPen = New-Object System.Drawing.Pen($rail, 10)
$g.DrawLine($railPen, 150, 830, 874, 830)
$heights = @(30, 62, 24, 110, 46, 150, 38, 72, 26, 54, 90, 34)
for ($i = 0; $i -lt $heights.Length; $i++) {
    $x = 168 + $i * 62
    $h = $heights[$i]
    $c = if ($i -eq 5) { $alert } else { $accent }
    $brush = New-Object System.Drawing.SolidBrush($c)
    $g.FillRectangle($brush, $x, 830 - $h, 26, $h)
}

# Process tree: one root, two children, three leaves.
$nodes = @(
    @{ x = 512; y = 190; r = 54; c = $accent },
    @{ x = 320; y = 420; r = 44; c = $accent },
    @{ x = 704; y = 420; r = 44; c = $accent },
    @{ x = 226; y = 640; r = 34; c = $accent },
    @{ x = 414; y = 640; r = 34; c = $accent },
    @{ x = 704; y = 640; r = 34; c = $alert }
)
$edges = @(@(0, 1), @(0, 2), @(1, 3), @(1, 4), @(2, 5))

$edgePen = New-Object System.Drawing.Pen($edge, 16)
$edgePen.StartCap = 'Round'
$edgePen.EndCap = 'Round'
foreach ($e in $edges) {
    $a = $nodes[$e[0]]
    $b = $nodes[$e[1]]
    $g.DrawLine($edgePen, [int]$a.x, [int]$a.y, [int]$b.x, [int]$b.y)
}

foreach ($n in $nodes) {
    $brush = New-Object System.Drawing.SolidBrush($n.c)
    $d = $n.r * 2
    $g.FillEllipse($brush, [int]($n.x - $n.r), [int]($n.y - $n.r), $d, $d)
}

$out = Join-Path $PSScriptRoot 'source.png'
$bmp.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose()
$bmp.Dispose()
Write-Host "wrote $out"
