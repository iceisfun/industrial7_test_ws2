# Guest-side runner: runs the listed test exes and frames every line on COM1.
#   WS2T begin <mode-list>        WS2T mode <adm|std>
#   WS2T start <exe>              WS2T out <exe> | <line>
#   WS2T rc <exe> <code|TIMEOUT> <secs>
#   WS2T stdkind <real-user|restricted-admin>   (std mode only: which unprivileged launcher was used)
#   WS2T done                     (only when every exe was attempted)
# Parameters: -Payload <dir>  -Modes adm,std  -Timeout <secs per exe>  -Full (also send RUN lines)
param([string]$Payload, [string]$Modes = 'adm', [int]$Timeout = 300, [switch]$Full)
$ErrorActionPreference = 'Continue'
$port = New-Object System.IO.Ports.SerialPort 'COM1', 115200, 'None', 8, 'One'
$port.WriteTimeout = 30000
$port.Open()
function Send([string]$s) {
    $s = ($s -replace '[^\x20-\x7e]', '?')
    $port.Write($s + "`r`n")
}
$work = 'C:\ws2t'
$bin = Join-Path $work 'bin'; $res = Join-Path $work 'results'; $cwd = Join-Path $work 'cwd'
New-Item -ItemType Directory -Force -Path $bin, $res, $cwd | Out-Null
Copy-Item -Recurse -Force (Join-Path $Payload 'bin\*') $bin
& icacls $work /grant 'Users:(OI)(CI)M' /T /C /Q | Out-Null
$list = @(Get-Content (Join-Path $Payload 'list.txt') | Where-Object { $_.Trim() })
$filter = ''
if (Test-Path (Join-Path $Payload 'filter.txt')) { $filter = (Get-Content (Join-Path $Payload 'filter.txt') -Raw).Trim() }
Send ("WS2T begin modes=$Modes exes=$($list.Count) timeout=$Timeout")
$os = (Get-CimInstance Win32_OperatingSystem)
Send ("WS2T os build=$($os.BuildNumber) version=$($os.Version) sku=$($os.OperatingSystemSKU) arch=$($os.OSArchitecture)")

$stdUser = 'ws2tstd'; $stdPass = 'Ws2t!Std-9x7Q-zz'; $stdReal = $false
function New-StdUser {
    & net user $stdUser /delete 2>&1 | Out-Null
    & net user $stdUser $stdPass /add /y /expires:never 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { return $false }
    & net user $stdUser /passwordchg:no 2>&1 | Out-Null
    # a standard account is a member of Users only; verify the launch really works before trusting it
    $probe = Join-Path $bin 'ws2_probe.exe'
    $o = & (Join-Path $bin 'ws2_runas.exe') --user $stdUser --pass $stdPass "`"$probe`"" 2>&1 | Out-String
    return ($o -match 'PROBE account=other-account') -and ($o -match 'is_elevated=0')
}
foreach ($mode in ($Modes -split ',')) {
    Send "WS2T mode $mode"
    if ($mode -eq 'std') {
        $stdReal = New-StdUser
        Send ("WS2T stdkind " + $(if ($stdReal) { 'real-user' } else { 'restricted-admin' }))
    }
    foreach ($exe in $list) {
        $exe = $exe.Trim()
        $path = Join-Path $bin "$exe.exe"
        $outf = Join-Path $res "$exe.$mode.txt"
        Send "WS2T start $exe"
        if (-not (Test-Path $path)) { Send "WS2T rc $exe MISSING 0"; continue }
        $xargs = if ($filter) { " $filter" } else { '' }
        $inner = "`"$path`"$xargs"
        if ($mode -eq 'std') {
            if ($stdReal) { $inner = "`"$bin\ws2_runas.exe`" --user $stdUser --pass $stdPass $inner" }
            else { $inner = "`"$bin\ws2_runas.exe`" --restricted $inner" }
        }
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "$env:ComSpec"
        $psi.Arguments = "/c `"$inner > `"$outf`" 2>&1`""
        $psi.WorkingDirectory = $cwd
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $p = [Diagnostics.Process]::Start($psi)
        $done = $p.WaitForExit($Timeout * 1000)
        $code = 'TIMEOUT'
        if ($done) { $code = $p.ExitCode } else { & taskkill /F /T /PID $p.Id 2>&1 | Out-Null; Start-Sleep -Milliseconds 500 }
        $secs = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        if (Test-Path $outf) {
            $fs = [IO.File]::Open($outf, 'Open', 'Read', 'ReadWrite')
            $sr = New-Object IO.StreamReader($fs)
            while (($line = $sr.ReadLine()) -ne $null) {
                if (-not $Full -and $line.StartsWith('RUN ')) { continue }
                Send "WS2T out $exe | $line"
            }
            $sr.Close()
        }
        Send "WS2T rc $exe $code $secs"
    }
}
if ($stdReal) { & net user $stdUser /delete 2>&1 | Out-Null }
Send 'WS2T done'
$port.Close()
exit 0
