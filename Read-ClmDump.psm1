Function Read-ClmDump
{
    [cmdletbinding()]
    param([switch]$scan, [switch]$scanforce, [switch]$latest, [switch]$latestforce, [string]$path)

    $BugcheckNames = @{
        'A'   = 'IRQL_NOT_LESS_OR_EQUAL'
        '19'  = 'BAD_POOL_HEADER'
        '1A'  = 'MEMORY_MANAGEMENT'
        '1E'  = 'KMODE_EXCEPTION_NOT_HANDLED'
        '24'  = 'NTFS_FILE_SYSTEM'
        '3B'  = 'SYSTEM_SERVICE_EXCEPTION'
        '4E'  = 'PFN_LIST_CORRUPT'
        '50'  = 'PAGE_FAULT_IN_NONPAGED_AREA'
        '74'  = 'BAD_SYSTEM_CONFIG_INFO'
        '7A'  = 'KERNEL_DATA_INPAGE_ERROR'
        '7B'  = 'INACCESSIBLE_BOOT_DEVICE'
        '7E'  = 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED'
        '7F'  = 'UNEXPECTED_KERNEL_MODE_TRAP'
        '8E'  = 'KERNEL_MODE_EXCEPTION_NOT_HANDLED'
        '9C'  = 'MACHINE_CHECK_EXCEPTION'
        '9F'  = 'DRIVER_POWER_STATE_FAILURE'
        'A0'  = 'INTERNAL_POWER_ERROR'
        'BE'  = 'ATTEMPTED_WRITE_TO_READONLY_MEMORY'
        'C1'  = 'SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION'
        'C2'  = 'BAD_POOL_CALLER'
        'C4'  = 'DRIVER_VERIFIER_DETECTED_VIOLATION'
        'C5'  = 'DRIVER_CORRUPTED_EXPOOL'
        'C7'  = 'TIMER_OR_DPC_INVALID'
        'CE'  = 'DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS'
        'D1'  = 'DRIVER_IRQL_NOT_LESS_OR_EQUAL'
        'D5'  = 'DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL'
        'D8'  = 'DRIVER_USED_EXCESSIVE_PTES'
        'E2'  = 'MANUALLY_INITIATED_CRASH'
        'EA'  = 'THREAD_STUCK_IN_DEVICE_DRIVER'
        'ED'  = 'UNMOUNTABLE_BOOT_VOLUME'
        'EF'  = 'CRITICAL_PROCESS_DIED'
        'F4'  = 'CRITICAL_OBJECT_TERMINATION'
        'F7'  = 'DRIVER_OVERRAN_STACK_BUFFER'
        'FC'  = 'ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY'
        'FE'  = 'BUGCODE_USB_DRIVER'
        '101' = 'CLOCK_WATCHDOG_TIMEOUT'
        '109' = 'CRITICAL_STRUCTURE_CORRUPTION'
        '10D' = 'WDF_VIOLATION'
        '113' = 'VIDEO_DXGKRNL_FATAL_ERROR'
        '116' = 'VIDEO_TDR_FAILURE'
        '117' = 'VIDEO_TDR_TIMEOUT_DETECTED'
        '119' = 'VIDEO_SCHEDULER_INTERNAL_ERROR'
        '124' = 'WHEA_UNCORRECTABLE_ERROR'
        '12B' = 'FAULTY_HARDWARE_CORRUPTED_PAGE'
        '133' = 'DPC_WATCHDOG_VIOLATION'
        '139' = 'KERNEL_SECURITY_CHECK_FAILURE'
        '13A' = 'KERNEL_MODE_HEAP_CORRUPTION'
        '141' = 'VIDEO_ENGINE_TIMEOUT_DETECTED'
        '144' = 'BUGCODE_USB3_DRIVER'
        '154' = 'UNEXPECTED_STORE_EXCEPTION'
        '161' = 'LIVE_SYSTEM_DUMP'
        '193' = 'VIDEO_DXGKRNL_LIVEDUMP'
        '1C8' = 'MANUALLY_INITIATED_POWER_BUTTON_HOLD'
        'C000021A' = 'STATUS_SYSTEM_PROCESS_TERMINATED'}
    
    $ExceptionNames = @{
        'C0000005' = 'ACCESS_VIOLATION'
        'C0000374' = 'HEAP_CORRUPTION'
        'C0000409' = 'STACK_BUFFER_OVERRUN'
        'C00000FD' = 'STACK_OVERFLOW'
        'C000001D' = 'ILLEGAL_INSTRUCTION'
        'C0000094' = 'INTEGER_DIVIDE_BY_ZERO'
        '80000003' = 'BREAKPOINT'
        'E06D7363' = 'CPP_EXCEPTION'
        'E0434352' = 'CLR_EXCEPTION (.NET)'}

    $DumpType = @{
        1 = 'Full'
        3 = 'Header'
        4 = 'Triage'
        5 = 'Bitmap'
        6 = 'Bitmap Kernel'}
    function Get-DumpFiles([switch]$force)
    {
        if($force){
            $dumpfolders = "C:\Windows\Minidump", "C:\ProgramData\Microsoft\Windows\WER\ReportArchive", "C:\ProgramData\Microsoft\Windows\WER\ReportQueue", "$env:LOCALAPPDATA\CrashDumps", "$env:USERPROFILE"
        }
        else{
            $dumpfolders = "C:\Windows\Minidump", "$env:USERPROFILE"
        }
        Write-Verbose "Searching $($dumpfolders -join ', ') (force: $force)"
        $dumpfile = @(Get-ChildItem -LiteralPath $dumpfolders -Recurse -File -Force:$force -ErrorAction SilentlyContinue | Where-Object {$_.Extension -in '.dmp', '.mdmp'})

        if($force -and (Test-Path -LiteralPath "C:\Windows\MEMORY.DMP")){
            $dumpfile += Get-Item -LiteralPath "C:\Windows\MEMORY.DMP" -Force
        }
        Write-Verbose "Found $($dumpfile.count) dumps"

        return $dumpfile
    }

    function Find-Dump([switch]$force)
    {
        $dumpfile = Get-DumpFiles -force:$force
        $sortdumpfile = $dumpfile | Sort-Object FullName -Unique
        $dumpfile = @($sortdumpfile)

        if($dumpfile.count -eq 0){
            throw "No dumps found, use -path"
        }
        if($dumpfile.count -eq 1){
            $dumppath = $dumpfile[0].FullName
         }
        if($dumpfile.count -gt 1){
            Write-Host "`nMore than one dump found`n"

            for($i=0;$i -lt $dumpfile.count;$i++){
                    Write-Host "$i. $($dumpfile[$i].fullname)"
                }
            do{
                [int]$choice = Read-Host "`nChoose dump"
                if($choice -lt 0 -or $choice -ge $dumpfile.count){
                    Write-Host "`nInvalid choice" -ForegroundColor Red
                    }
                }
            until($choice -ge 0 -and $choice -lt $dumpfile.count)
        $chosendump = $dumpfile[$choice].fullname
        $dumppath = $chosendump
        }

        return $dumppath
    }

    function Get-LatestDump([switch]$force)
    {
        $latestdumpfile = Get-DumpFiles -force:$force | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if($null -eq $latestdumpfile){
            throw "No dumps found, use -path"
        }
        $dumppath = $latestdumpfile.fullname

        return $dumppath
    }
    function Read-DumpBytes($dumpfile, $bytesize)
    {
        $filesize = (Get-Item -LiteralPath $dumpfile -ErrorAction Stop).Length
        if($bytesize -le 0 -or $bytesize -gt $filesize){
            $bytesize = $filesize
        }
        Write-Verbose "Reading $bytesize of $filesize bytes"
        if ($PSVersionTable.PSVersion.Major -ge 6){
            Get-Content -LiteralPath $dumpfile -AsByteStream -ReadCount $bytesize -TotalCount $bytesize -ErrorAction Stop
        }
        else{
            Get-Content -LiteralPath $dumpfile -Encoding Byte -ReadCount $bytesize -TotalCount $bytesize -ErrorAction Stop
        }
    }

    function Get-Hex($bytes, $off, $size)
    {
        -join ($bytes[($off+$size-1)..$off] | ForEach-Object { '{0:x2}' -f $_})
    }

    function Get-Num($bytes, $off, $size)
    {
        if ($off + $size -gt $bytes.Count){
            throw('Read past end of loaded bytes at offset 0x{0:X}' -f $off)
        }
        [uint64]$v = 0
        for($i = $size - 1;$i -ge 0; $i--){
            $v = $v * [uint64]256 + [uint64]$bytes[$off + $i]
        }
    return $v
    }
    function Get-MdmpString($bytes, $rva)
    {
        $length = Get-Num $bytes $rva 4
        $start = $rva + 4
        if ($start + $length -gt $bytes.Count){
            throw('String at 0x{0:X} goes past end of loaded bytes' -f $rva)
        }
        $chars = for ($i = 0; $i -lt $length; $i += 2) {
        [char][int]($bytes[$start + $i] + 256 * $bytes[$start + $i + 1])
    }
    -join $chars
    }
    function Get-Stream($bytes, $type)
    {
        $count = Get-Num $bytes 8 4
        $directory = Get-Num $bytes 12 4
        for ($n = 0; $n -lt $count; $n++){
            $e = $directory + 12 * $n
            if((Get-Num $bytes $e 4) -eq $type){
                return (Get-Num $bytes ($e + 8) 4)
            }
        }
    return $null
    }
    function Get-DumpText($bytes, $off, $size)
    {
        -join($bytes[$off..($off+$size-1)] | ForEach-Object {[char]$_})
    }

    function Select-Dump ($dumpfile)
    {
        $selectdump = [ordered]@{}

        $bytes = Read-DumpBytes $dumpfile 10
        Write-Verbose "Signature bytes read: $($bytes.Count)"

        $selectdump.DumpFile = $dumpfile

        $selectdump.Sig = Get-DumpText $bytes 0 4

        if($selectdump.Sig -notin 'PAGE' , 'MDMP'){
            throw "Signature not recgonized $($selectdump.Sig)"
        }
        return $selectdump
    }

    function Add-Cdb ($dumpfile)
    {
        $cdbdump = cdb -z "$dumpfile" -c "!analyze -v;q"
        $cdbchecks = $cdbdump | Select-String -SimpleMatch "FILE_IN_CAB", "BUGCHECK_CODE" , "IMAGE_NAME", "MODULE_NAME", "FAILURE_BUCKET_ID", "PROCESS_NAME", "SYMBOL_NAME"
        ConvertFrom-StringData($cdbchecks -join "`n" -replace ':' , '=')
    }

    ##########################################################HELPER FUNCTIONS END#########################################################################
    function Read-Pagedu64 ($dumpfile)
    {
        $checks = [ordered]@{}

        $bytes = Read-DumpBytes $dumpfile 8192
        $checks.DumpSignature = Get-DumpText $bytes 0 8
        Write-Verbose "PAGEDU64 header loaded, signature $($checks.DumpSignature)"
        if($checks.DumpSignature -eq 'PAGEDU64'){
            do{
                $pageyn = Read-Host "`nThis is a PAGEDU64 dump, would you like to add info from CDB to this dump?"
            }
            until($pageyn -in 'y' , 'n')
            if($pageyn -eq 'y'){
                Add-Cdb $dumpfile
            }
            if($pageyn -eq 'n'){
                Write-Host "`nContinuing..." -ForegroundColor Green
            }
        }
        if($checks.DumpSignature -ne 'PAGEDU64'){
            $checks.Error = 'Not a PAGEDU64 dump' ; return $checks
        }

        $minorver = Get-hex $bytes 12 4
        $checks.Build = [uint32]"0x$minorver"

        $checks.Architecture = Get-Hex $bytes 48 4
        if($checks.Architecture -eq '00008664'){
            $checks.Architecture = 'x64'
        }
        else{
            $checks.Error = 'Not x64' ; return $checks
        }

        $cpu = Get-Hex $bytes 52 4
        $checks.Processors = [uint32]"0x$cpu"

        $bugcheckcodenum = Get-Num $bytes 56 4
        if($bugcheckcodenum -ge 0x10000000 -and $bugcheckcodenum -lt 0x20000000){
            $bugcheckcodenum = $bugcheckcodenum - [uint64]0x10000000
        }
        $bugcheckcode = '{0:X}' -f $bugcheckcodenum
        $checks.BugcheckCode = '0x' + $bugcheckcode
        if($BugcheckNames.ContainsKey($bugcheckcode)){
            $checks.Bugcheck = $BugcheckNames[$bugcheckcode]
        }
        else{
            $checks.Bugcheck = 'Unknown'
        }
        $checks.Param1 = '0x{0:X16}' -f (Get-Num $bytes 64 8)
        $checks.Param2 = '0x{0:X16}' -f (Get-Num $bytes 72 8)
        $checks.Param3 = '0x{0:X16}' -f (Get-Num $bytes 80 8)
        $checks.Param4 = '0x{0:X16}' -f (Get-Num $bytes 88 8)
        $dumptypehex = Get-Hex $bytes 3992 4
        $dumptypecode = [int]("0x"+($dumptypehex))
        if($DumpType.ContainsKey($dumptypecode)){
            $checks.Type = $DumpType[$dumptypecode]
        }
        else{
            $checks.Error = 'Dump type not in table' ; return $checks
        }
        
        Write-Verbose "Bugcheck $bugcheckcode, dump type $dumptypecode"
        
        $crashtime = Get-Hex $bytes 4008 8
        $crash = (Get-Date '1601-01-01').AddTicks([int64]("0x" + $crashtime))
        $checks.CrashTimeUTC = $crash.ToString('yyyy-MM-dd HH:mm:ss')
        $checks.CrashTimeLocal = $crash.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
        $uptime = Get-Hex $bytes 4144 8
        $secs = [int64](("0x" + ($uptime)) / 10000000)
        $up = New-TimeSpan -Seconds $secs
        $checks.Uptime = '{0}d {1}h {2}m' -f $up.Days, $up.Hours, $up.Minutes

    return $checks
    }
    function Read-Mdmp ($dumpfile)
    {
    $mdmpchecks = [ordered]@{}

    $headerbytes = Read-DumpBytes $dumpfile 4096
    $streamcount = Get-Num $headerbytes 8 4
    $directory = Get-Num $headerbytes 12 4
    $directoryend = $directory + 12 * $streamcount
    if($directoryend -gt $headerbytes.Count){
        $headerbytes = Read-DumpBytes $dumpfile $directoryend
    }

    Write-Verbose "$streamcount streams, directory at $directory"
    $needbytes = $directoryend
    for($n = 0; $n -lt $streamcount; $n++){
        $e = $directory + 12 * $n
        if((Get-Num $headerbytes $e 4) -in 3, 4, 6, 7, 15){
            $streamend = (Get-Num $headerbytes ($e + 8) 4) + (Get-Num $headerbytes ($e + 4) 4)
            if($streamend -gt $needbytes){
                $needbytes = $streamend
            }
        }
    }
   
    Write-Verbose "Streams we need end at byte $needbytes"
    $bytes = Read-DumpBytes $dumpfile ($needbytes + 1048576)

    $mdmpchecks.Signature = Get-DumpText $bytes 0 4
    $mdmpchecks.NumberOfStreams = Get-Num $bytes 8 4
    $mdmpchecks.StreamDirectory = Get-Num $bytes 12 4
    $crashseconds = Get-Num $bytes 20 4
    $crash = (Get-Date '1970-01-01').AddSeconds($crashseconds)
    $mdmpchecks.CrashTimeUTC = $crash.ToString('yyyy-MM-dd HH:mm:ss')
    $mdmpchecks.CrashTimeLocal = $crash.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')

    $system = Get-Stream $bytes 7
    Write-Verbose "SystemInfo at $system"
    
    if($null -ne $system){
        $arch = Get-Num $bytes $system 2
        $mdmpchecks.Architecture = switch ($arch){
            0 {'x86'} 5 {'ARM'} 9 {'x64'} 12 {'ARM64'} default {"Unknown ($arch)"}
        }
        $mdmpchecks.Processors = $bytes[$system + 6]
        $mdmpchecks.Build = Get-Num $bytes ($system + 16) 4
    }

    $misc = Get-Stream $bytes 15
    Write-Verbose "MiscInfo at $misc"
    
    if($null -ne $misc){
        $miscflags = $bytes[$misc + 4]
        if($miscflags -band 1){
            $mdmpchecks.ProcessId = Get-Num $bytes ($misc + 8) 4
        }
        if($miscflags -band 2){
            $createseconds = Get-Num $bytes ($misc + 12) 4
            $created = (Get-Date '1970-01-01').AddSeconds($createseconds)
            $mdmpchecks.ProcessStartLocal = $created.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
            if($crashseconds -ge $createseconds){
                $up = New-TimeSpan -Seconds ($crashseconds - $createseconds)
                $mdmpchecks.ProcessUptime = '{0}d {1}h {2}m {3}s' -f $up.Days, $up.Hours, $up.Minutes, $up.Seconds
            }
        }
    }

    $exception = Get-Stream $bytes 6
    Write-Verbose "Exception at $exception"
    
    $address = $null
    $accessaddress = $null
    $codedhex = $null
    if($null -eq $exception){
        $mdmpchecks.Exception = 'No crash recorded, manual or hang dump'
    }
    else{
        $mdmpchecks.FaultingThread = Get-Num $bytes $exception 4
        $codedhex = '{0:X8}' -f (Get-Num $bytes ($exception + 8) 4)
        $mdmpchecks.ExceptionCode = '0x' + $codedhex
        $mdmpchecks.ExceptionName = if($ExceptionNames.ContainsKey($codedhex)){
            $ExceptionNames[$codedhex]
        }
        else{
            'Unknown'
        }
        $address = Get-Num $bytes ($exception + 24) 8
        $mdmpchecks.ExceptionAddress = '0x{0:X16}' -f $address

        if($codedhex -eq 'C0000005'){
            $type = Get-Num $bytes ($exception + 40) 8
            $mdmpchecks.AccessType = switch ($type){
                0{'Read'} 1 {'Write'} 8 {'Execute'} default {$type}
            }
            $accessaddress = Get-Num $bytes ($exception + 48) 8
            $mdmpchecks.AccessAddress = '0x{0:X16}' -f $accessaddress
        }
        $context = Get-Num $bytes ($exception + 164) 4
        if($mdmpchecks.Architecture -eq 'x64' -and $context -gt 0){
            $mdmpchecks.RIP = '0x{0:X16}' -f (Get-Num $bytes ($context + 248) 8)
            $mdmpchecks.RSP = '0x{0:X16}' -f (Get-Num $bytes ($context + 152) 8)
        }
    }

    $modules = Get-Stream $bytes 4
    Write-Verbose "ModuleList at $modules"
    
    $modulelist = @()
    $faultmodule = $null
    $lowest = [uint64]::MaxValue
    $highest = [uint64]0
    if($null -ne $modules){
        $count = Get-Num $bytes $modules 4
        if($modules + 4 + 108 * $count -gt $bytes.Count){
            $mdmpchecks.Error = "Module count $count doesnt fit in loaded bytes" ; return $mdmpchecks
        }
        for($i=0; $i -lt $count; $i++){
            $e = $modules + 4 + 108 *$i
            $base = Get-Num $bytes $e 8
            $size = Get-Num $bytes ($e + 8) 4
            $modulepath = Get-MdmpString $bytes (Get-Num $bytes ($e + 20) 4)
            $modulelist += @{
                Base    = $base
                End     = $base + $size
                Path    = $modulepath
                Name    = Split-Path $modulepath -Leaf
                Windows = $modulepath -like "$env:windir\*"
                Version = '{0}.{1}.{2}.{3}' -f (Get-Num $bytes ($e + 34) 2), (Get-Num $bytes ($e + 32) 2), (Get-Num $bytes ($e + 38) 2), (Get-Num $bytes ($e + 36) 2)
            }
            if($base -lt $lowest){ $lowest = $base }
            if($base + $size -gt $highest){ $highest = $base + $size }
        }
        Write-Verbose "$($modulelist.Count) modules loaded"
        $mdmpchecks.Process = $modulelist[0].Path
        
        if($null -ne $address){
            $faultmodule = $modulelist | Where-Object {$address -ge $_.Base -and $address -lt $_.End} | Select-Object -First 1
            if($faultmodule){
                $mdmpchecks.FaultingModule = $faultmodule.Name
                $mdmpchecks.ModuleVersion  = $faultmodule.Version
                $mdmpchecks.FaultOffset    = '+0x{0:X}' -f ($address - $faultmodule.Base)
            }
            else{
                $mdmpchecks.FaultingModule = 'Address not in any loaded module'
            }
        }
    }

    $threads = Get-Stream $bytes 3
    Write-Verbose "ThreadList at $threads"
    if($null -ne $threads){
        $threadcount = Get-Num $bytes $threads 4
        if($threads + 4 + 48 * $threadcount -gt $bytes.Count){
            $mdmpchecks.Error = "Thread count $threadcount doesnt fit in loaded bytes" ; return $mdmpchecks
        }
        $mdmpchecks.ThreadCount = $threadcount
        for($x=0; $x -lt $threadcount; $x++){
            $t = $threads + 4 + 48 * $x
            $threadid = Get-Num $bytes $t 4
            if(($null -eq $mdmpchecks.FaultingThread -and $x -eq 0) -or $threadid -eq $mdmpchecks.FaultingThread){
                $mdmpchecks.StackThread = $threadid
                $mdmpchecks.StackStart = '0x{0:X16}' -f (Get-Num $bytes ($t + 24) 8)
                $mdmpchecks.StackSize  = Get-Num $bytes ($t + 32) 4
                $mdmpchecks.StackRva   = Get-Num $bytes ($t + 36) 4
                break
            }
        }
    }

    $stackhits = @()
    $firstnonwindows = $null
    $firstthirdparty = $null
    $thirdparty = @()
    $appfolder = ''
    if($mdmpchecks.Process){
        $appfolder = Split-Path $mdmpchecks.Process -Parent
    }
    $stackrva = $mdmpchecks.StackRva
    $stacksize = $mdmpchecks.StackSize
    if($stackrva -eq 0 -and $null -ne $mdmpchecks.StackThread){
        $mdmpchecks.StackModules = 'Stack not stored with the thread (full-memory dump?)'
    }
    if($stackrva -gt 0 -and $modulelist.Count -gt 0){
        if($stackrva + $stacksize -gt $bytes.Count){
            Write-Verbose "Stack is past loaded bytes, reading up to $($stackrva + $stacksize)"
            $bytes = Read-DumpBytes $dumpfile ($stackrva + $stacksize)
        }
        Write-Verbose "Scanning $stacksize bytes of stack"
        $lastname = ''
        for($s = 0; $s -le $stacksize - 8; $s += 8){
            $value = Get-Num $bytes ($stackrva + $s) 8
            if($value -lt $lowest -or $value -ge $highest){ continue }
            foreach($m in $modulelist){
                if($value -ge $m.Base -and $value -lt $m.End){
                    if($m.Name -ne $lastname){
                        $stackhits += '{0,2}. {1}+0x{2:X}' -f $stackhits.Count, $m.Name, ($value - $m.Base)
                        $lastname = $m.Name
                        if(-not $m.Windows -and $null -eq $firstnonwindows){
                            $firstnonwindows = $m.Name
                        }
                        if(-not $m.Windows -and -not ($m.Path -like "$appfolder\*")){
                            if($null -eq $firstthirdparty){
                                $firstthirdparty = $m
                            }
                            if($thirdparty -notcontains $m.Name){
                                $thirdparty += $m.Name
                            }
                        }
                    }
                    break
                }
            }
            if($stackhits.Count -ge 15){ break }
        }
        $mdmpchecks.StackModules = $stackhits -join "`n"
        if($thirdparty.Count -gt 0){
            $mdmpchecks.ThirdPartyOnStack = $thirdparty -join ', '
        }
    }

    if($mdmpchecks.Process){
        $processname = Split-Path $mdmpchecks.Process -Leaf
    }
    else{
        $processname = 'Process'
    }
    if($null -eq $exception){
        $summary = "$processname dump with no crash recorded (manual or hang dump) checked main thread $($mdmpchecks.StackThread)"
    }
    else{
        $summary = "$processname crashed with $($mdmpchecks.ExceptionName) ($($mdmpchecks.ExceptionCode))"
        if($null -ne $accessaddress){
            $summary += " - $($mdmpchecks.AccessType) of $($mdmpchecks.AccessAddress)"
            if($accessaddress -lt 0x10000){
                $summary += ' (null pointer)'
            }
        }
        if($faultmodule){
            $summary += " in $($faultmodule.Name)$($mdmpchecks.FaultOffset)"
        }
    }
    
    if($firstthirdparty){
        $suspect = "$($firstthirdparty.Name) $($firstthirdparty.Version) third party module on the stack: $($firstthirdparty.Path)"
    }
    elseif($faultmodule -and -not $faultmodule.Windows){
        $suspect = "$($faultmodule.Name) $($faultmodule.Version) crash is in the app's own code"
    }
    elseif($firstnonwindows){
        $suspect = "$firstnonwindows, first non-Windows module on the stack"
    }
    else{
        $suspect = 'No third-party module found'
    }
    
    $mdmpchecks.Summary = $summary
    $mdmpchecks.Suspect = $suspect
    Write-Verbose "MDMP parse done"
    return $mdmpchecks
    }

    $onlyone = 0

    if($scan) {$onlyone++}
    if($scanforce) {$onlyone++}
    if($latest) {$onlyone++}
    if($latestforce) {$onlyone++}
    if($path) {$onlyone++}
    if($onlyone -ne 1) {throw "Use only one switch (-scan, -scanforce, -latest, -latestforce, or -path)"}

    if($scan){
        $dumpfile = Find-Dump
    }
    elseif($scanforce){
        $dumpfile = Find-Dump -force
    }
    elseif($latest){
        $dumpfile = Get-LatestDump
    }
    elseif($latestforce){
        $dumpfile = Get-LatestDump -force
    }
    elseif($path){
        $dumpfile = $path
    }

    Write-Verbose "Selected $dumpfile"
    $selectedump = Select-Dump $dumpfile
    Write-Verbose "Signature $($selectedump.Sig)"

    if($selectedump.Sig -eq 'PAGE'){
        $result = Read-Pagedu64 $dumpfile
    }
    if($selectedump.sig -eq 'MDMP'){
        $result = Read-Mdmp $dumpfile
    }

    Write-Verbose "Parsing finished"
    return ($result | ConvertTo-Json | ConvertFrom-Json)
}
Set-Alias -Name dumparser -Value Read-ClmDump
Export-ModuleMember -Function Read-ClmDump -Alias dumparser