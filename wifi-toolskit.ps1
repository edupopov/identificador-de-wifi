<#
.SYNOPSIS
  Utilitário para:
  - Listar redes Wi-Fi
  - Mostrar senhas
  - Mostrar características (WPA/AES etc.)
  - Listar adaptadores Wi-Fi (hardware + rede + IP + banda + driver)
  - Backup/restauração de perfis Wi-Fi (XML)
  - Excluir perfil Wi-Fi específico
  - Diagnóstico de rede (ping / tracert / arp)
  - Scanner de redes Wi-Fi (site survey básico)
  - Criar novo perfil Wi-Fi (XML + netsh)
  - Listar perfis WPA-Enterprise + certificados de cliente (Client Auth)

.OBS
  - Recomenda-se executar o PowerShell como Administrador.
  - Usa "netsh wlan", Win32_NetworkAdapter, Win32_NetworkAdapterConfiguration,
    Win32_PnPEntity, Win32_PnPSignedDriver e Cert:\.
#>

try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new() } catch {}

#-------------------- Funções auxiliares --------------------#

function Get-CIDRFromMask {
    param(
        [Parameter(Mandatory)][string] $Mask
    )
    if (-not $Mask) { return $null }

    $octets = $Mask.Split('.')
    if ($octets.Count -ne 4) { return $null }

    $bits = 0
    foreach ($octet in $octets) {
        [int]$n = 0
        if (-not [int]::TryParse($octet, [ref]$n)) { return $null }

        while ($n -gt 0) {
            $bits += ($n -band 1)
            $n = $n -shr 1
        }
    }
    return $bits
}

function Get-WifiBandFromChannel {
    param(
        [Parameter(Mandatory)][int] $Channel
    )
    if ($Channel -ge 1 -and $Channel -le 14) {
        return "2.4 GHz"
    } elseif ($Channel -ge 32 -and $Channel -le 196) {
        return "5 GHz"
    } elseif ($Channel -gt 196) {
        return "6 GHz / Outra"
    } else {
        return "Desconhecida"
    }
}

function Escape-Xml {
    param(
        [string] $Text
    )
    if ($null -eq $Text) { return "" }
    $t = $Text
    $t = $t -replace '&','&amp;'
    $t = $t -replace '<','&lt;'
    $t = $t -replace '>','&gt;'
    $t = $t -replace '"','&quot;'
    $t = $t -replace "'","&apos;"
    return $t
}

function Get-WifiProfiles {
    $output = netsh wlan show profiles 2>$null
    if (-not $output) { return @() }

    $profiles = @()
    foreach ($line in $output) {
        if ($line -notmatch ":") { continue }
        $parts = $line.Split(":", 2)
        if ($parts.Count -ne 2) { continue }
        $left  = $parts[0].Trim()
        $right = $parts[1].Trim()
        if (-not $right) { continue }

        if ($left -match "Perfi" -or $left -match "Profile") {
            $profiles += $right
        }
    }
    return ($profiles | Sort-Object -Unique)
}

function Select-WifiProfile {
    param(
        [string] $Titulo = "Selecione uma rede Wi-Fi:"
    )

    $profiles = Get-WifiProfiles

    if (-not $profiles -or $profiles.Count -eq 0) {
        Write-Host "Nenhuma rede Wi-Fi encontrada neste equipamento." -ForegroundColor Yellow
        return $null
    }

    Write-Host ""
    Write-Host "=== $Titulo ===" -ForegroundColor Cyan
    for ($i = 0; $i -lt $profiles.Count; $i++) {
        Write-Host ("[{0}] {1}" -f ($i + 1), $profiles[$i])
    }
    Write-Host "[0] Voltar ao menu anterior"
    Write-Host ""

    $choice = Read-Host "Digite o número da rede desejada"

    if ($choice -eq "0" -or [string]::IsNullOrWhiteSpace($choice)) {
        return $null
    }

    [int]$index = 0
    if (-not [int]::TryParse($choice, [ref]$index)) {
        Write-Host "Opção inválida." -ForegroundColor Red
        return $null
    }

    $index = $index - 1
    if ($index -lt 0 -or $index -ge $profiles.Count) {
        Write-Host "Opção fora da faixa." -ForegroundColor Red
        return $null
    }

    return $profiles[$index]
}

#-------------------- Perfis / senhas --------------------#

function Show-WifiPassword {
    $profile = Select-WifiProfile -Titulo "Selecione a rede para exibir a senha"
    if (-not $profile) { return }

    Write-Host ""
    Write-Host "Obtendo dados da rede '$profile'..." -ForegroundColor Cyan

    $details = netsh wlan show profile name="$profile" key=clear 2>$null
    if (-not $details) {
        Write-Host "Não foi possível obter detalhes desta rede." -ForegroundColor Red
        return
    }

    $keyLine = $details | Select-String "Key Content|Conteúdo da Chave"
    if (-not $keyLine) {
        Write-Host "Senha não encontrada. Pode ser um perfil sem chave ou sem permissões suficientes." -ForegroundColor Yellow
        return
    }

    $text  = $keyLine.ToString()
    $parts = $text.Split(":", 2)
    $senha = if ($parts.Count -eq 2) { $parts[1].Trim() } else { $null }

    Write-Host ""
    Write-Host "=== SENHA DA REDE '$profile' ===" -ForegroundColor Green
    if ($senha) {
        Write-Host "Senha: $senha" -ForegroundColor White
    } else {
        Write-Host "Não foi possível extrair a senha." -ForegroundColor Yellow
    }
}

function Show-WifiCharacteristics {
    $profile = Select-WifiProfile -Titulo "Selecione a rede para exibir características"
    if (-not $profile) { return }

    Write-Host ""
    Write-Host "Obtendo características da rede '$profile'..." -ForegroundColor Cyan

    $details = netsh wlan show profile name="$profile" key=clear 2>$null
    if (-not $details) {
        Write-Host "Não foi possível obter detalhes desta rede." -ForegroundColor Red
        return
    }

    $authLines   = $details | Select-String "Authentication|Autenticação"
    $cipherLines = $details | Select-String "Cipher|Cifra"

    $authList  = @()
    foreach ($line in $authLines) {
        $p = $line.ToString().Split(":",2)
        if ($p.Count -eq 2) { $authList += $p[1].Trim() }
    }
    $authList = $authList | Select-Object -Unique

    $cipherList = @()
    foreach ($line in $cipherLines) {
        $p = $line.ToString().Split(":",2)
        if ($p.Count -eq 2) { $cipherList += $p[1].Trim() }
    }
    $cipherList = $cipherList | Select-Object -Unique

    Write-Host ""
    Write-Host "=== CARACTERÍSTICAS DA REDE '$profile' ===" -ForegroundColor Green
    Write-Host ("Autenticação (Ex.: WPA/WPA2/WPA3): {0}" -f ($authList -join ", "))
    Write-Host ("Criptografia (Ex.: TKIP/AES/GCMP): {0}" -f ($cipherList -join ", "))
    Write-Host ""
}

function Show-WifiList {
    $profiles = Get-WifiProfiles
    if (-not $profiles -or $profiles.Count -eq 0) {
        Write-Host "Nenhuma rede Wi-Fi encontrada neste equipamento." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "=== Redes Wi-Fi neste equipamento ===" -ForegroundColor Green
    $i = 1
    foreach ($p in $profiles) {
        Write-Host ("[{0}] {1}" -f $i, $p)
        $i++
    }
    Write-Host ""
}

#-------------------- Interfaces / adaptadores --------------------#

function Get-WifiInterfaces {
    # Lê "netsh wlan show interfaces" e retorna Nome + SSID + BSSID + Signal + Channel + RadioType
    $output = netsh wlan show interfaces 2>$null
    if (-not $output) { return @() }

    $interfaces = @()
    $current = [ordered]@{}

    foreach ($line in $output) {

        if ($line -match "^\s*(Name|Nome)\s*:\s*(.+)$") {
            if ($current.Contains("Name")) {
                $interfaces += [PSCustomObject]$current
                $current = [ordered]@{}
            }
            $current.Name = $Matches[2].Trim()
            continue
        }

        if ($line -match "^\s*SSID\s*:\s*(.+)$") {
            $current.SSID = $Matches[1].Trim()
            continue
        }

        if ($line -match "^\s*BSSID\s*:\s*(.+)$") {
            $current.BSSID = $Matches[1].Trim()
            continue
        }

        if ($line -match "^\s*(Signal|Sinal)\s*:\s*(\d+)%") {
            $current.SignalPercent = [int]$Matches[2]
            continue
        }

        if ($line -match "^\s*(Channel|Canal)\s*:\s*(\d+)") {
            $current.Channel = [int]$Matches[2]
            continue
        }

        if ($line -match "^\s*(Radio type|Tipo de rádio)\s*:\s*(.+)$") {
            $current.RadioType = $Matches[2].Trim()
            continue
        }
    }

    if ($current.Contains("Name")) {
        $interfaces += [PSCustomObject]$current
    }

    return $interfaces
}

function Show-WifiAdapters {
    Write-Host ""
    Write-Host "Obtendo adaptadores Wi-Fi (hardware + rede + IP + banda + driver)..." -ForegroundColor Cyan

    $adapters = Get-CimInstance Win32_NetworkAdapter -ErrorAction SilentlyContinue |
        Where-Object {
            $_.NetEnabled -eq $true -and (
                $_.Name            -match "Wireless|Wi-?Fi|802\.11" -or
                $_.Description     -match "Wireless|Wi-?Fi|802\.11" -or
                $_.NetConnectionID -match "Wi-?Fi|Wireless"
            )
        }

    if (-not $adapters) {
        Write-Host "Nenhum adaptador Wi-Fi encontrado." -ForegroundColor Yellow
        return
    }

    $wifiIfaces = Get-WifiInterfaces
    $ipConfigs  = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE" -ErrorAction SilentlyContinue
    $drvInfo    = Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue

    $result = @()

    foreach ($ad in $adapters) {

        $mac    = $ad.MACAddress
        $status = switch ($ad.NetConnectionStatus) {
            2 { "Conectado" }
            7 { "Desconectado" }
            default { "Status:$($_)" }
        }

        $iface = $null
        if ($ad.NetConnectionID) {
            $iface = $wifiIfaces | Where-Object { $_.Name -eq $ad.NetConnectionID } | Select-Object -First 1
        }

        $ssid      = $null
        $bssid     = $null
        $signal    = $null
        $channel   = $null
        $radioType = $null
        $band      = $null

        if ($iface) {
            $ssid      = $iface.SSID
            $bssid     = $iface.BSSID
            $signal    = $iface.SignalPercent
            $channel   = $iface.Channel
            $radioType = $iface.RadioType

            if ($channel) {
                $band = Get-WifiBandFromChannel -Channel $channel
            }
        }

        if (-not $ssid)   { $ssid   = "(não conectado)" }
        if (-not $signal) { $signal = 0 }

        $cfg = $null
        if ($mac) {
            $cfg = $ipConfigs | Where-Object { $_.MACAddress -eq $mac } | Select-Object -First 1
        }

        $ipv4     = $null
        $subnet   = $null
        $gateway  = $null
        $dnsList  = $null
        $cidr     = $null

        if ($cfg) {
            if ($cfg.IPAddress) {
                $ipv4 = ($cfg.IPAddress | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -First 1)
            }
            if ($cfg.IPSubnet) {
                $subnet = ($cfg.IPSubnet | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -First 1)
            }
            if ($cfg.DefaultIPGateway) {
                $gateway = ($cfg.DefaultIPGateway | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -First 1)
            }
            if ($cfg.DNSServerSearchOrder) {
                $dnsList = $cfg.DNSServerSearchOrder -join ", "
            }

            if ($subnet) {
                $cidr = Get-CIDRFromMask -Mask $subnet
            }
        }

        $pnp = Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue |
               Where-Object { $_.DeviceID -eq $ad.PNPDeviceID }

        $hwId = $null
        if ($pnp -and $pnp.HardwareID) {
            $hwId = ($pnp.HardwareID | Select-Object -First 2) -join " | "
        }

        $driver      = $null
        $driverName  = $null
        $driverVer   = $null
        if ($drvInfo) {
            $driver = $drvInfo | Where-Object { $_.DeviceID -eq $ad.PNPDeviceID } | Select-Object -First 1
            if ($driver) {
                $driverName = $driver.DriverName
                $driverVer  = $driver.DriverVersion
            }
        }

        $result += [PSCustomObject]@{
            Nome          = $ad.Name
            Conexao       = $ad.NetConnectionID
            MAC           = $mac
            SSID          = $ssid
            BSSID         = $bssid
            Signal        = $signal
            Status        = $status
            Banda         = $band
            Canal         = $channel
            RadioType     = $radioType
            IPv4          = $ipv4
            Subnet        = $subnet
            CIDR          = $cidr
            Gateway       = $gateway
            DNS           = $dnsList
            PNPDeviceID   = $ad.PNPDeviceID
            HardwareID    = $hwId
            DriverName    = $driverName
            DriverVersion = $driverVer
        }
    }

    Write-Host ""
    Write-Host "=== ADAPTADORES WI-FI ENCONTRADOS ===" -ForegroundColor Green

    $index = 1
    foreach ($item in $result) {
        Write-Host ("[{0}] {1}" -f $index, $item.Nome) -ForegroundColor Cyan
        Write-Host ("    Conexão......: {0}" -f $item.Conexao)
        Write-Host ("    MAC..........: {0}" -f $item.MAC)
        Write-Host ("    SSID.........: {0}" -f $item.SSID)
        if ($item.BSSID) {
            Write-Host ("    BSSID........: {0}" -f $item.BSSID)
        }
        Write-Host ("    Força sinal..: {0} %" -f $item.Signal)
        Write-Host ("    Status.......: {0}" -f $item.Status)

        if ($item.Banda) {
            Write-Host ("    Banda........: {0}" -f $item.Banda)
        }
        if ($item.Canal) {
            Write-Host ("    Canal........: {0}" -f $item.Canal)
        }
        if ($item.RadioType) {
            Write-Host ("    Tipo rádio...: {0}" -f $item.RadioType)
        }

        if ($item.IPv4) {
            $cidrStr = if ($item.CIDR) { " /$($item.CIDR)" } else { "" }
            Write-Host ("    IPv4.........: {0}" -f $item.IPv4)
            if ($item.Subnet) {
                Write-Host ("    Máscara......: {0}{1}" -f $item.Subnet, $cidrStr)
            }
            if ($item.Gateway) {
                Write-Host ("    Gateway......: {0}" -f $item.Gateway)
            }
            if ($item.DNS) {
                Write-Host ("    DNS..........: {0}" -f $item.DNS)
            }
        } else {
            Write-Host ("    IPv4.........: (sem IP configurado)") -ForegroundColor DarkYellow
        }

        if ($item.DriverName -or $item.DriverVersion) {
            Write-Host ("    Driver.......: {0} {1}" -f $item.DriverName, $item.DriverVersion)
        }

        if ($item.HardwareID) {
            Write-Host ("    HardwareID...: {0}" -f $item.HardwareID)
        }
        Write-Host ("    PNPDeviceID..: {0}" -f $item.PNPDeviceID) -ForegroundColor DarkGray
        Write-Host ""
        $index++
    }

    Write-Host "Banda estimada a partir do canal: 1-14 → 2.4 GHz; 32-196 → 5 GHz; >196 → 6 GHz/Outra." -ForegroundColor DarkGray
    Write-Host "CIDR calculado a partir da máscara de sub-rede IPv4." -ForegroundColor DarkGray
}

#-------------------- BACKUP / RESTAURAÇÃO --------------------#

function Backup-WifiProfiles {
    Write-Host ""
    $defaultFolder = Join-Path $env:USERPROFILE ("Desktop\WiFiBackup_" + (Get-Date -Format 'yyyyMMdd_HHmmss'))
    Write-Host "Backup de perfis Wi-Fi (export XML com senha - key=clear)" -ForegroundColor Cyan
    Write-Host "Pasta padrão sugerida: $defaultFolder"
    $folder = Read-Host "Informe a pasta de destino (ENTER para usar a padrão)"

    if ([string]::IsNullOrWhiteSpace($folder)) {
        $folder = $defaultFolder
    }

    if (-not (Test-Path -LiteralPath $folder)) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
    }

    Write-Host ""
    Write-Host "Exportando todos os perfis Wi-Fi para: $folder" -ForegroundColor Green

    & netsh wlan export profile key=clear folder="$folder" | Out-Null

    $xmlFiles = Get-ChildItem -Path $folder -Filter *.xml -ErrorAction SilentlyContinue

    if (-not $xmlFiles) {
        Write-Host "Nenhum arquivo XML de perfil foi gerado. Verifique permissões e perfis existentes." -ForegroundColor Yellow
    } else {
        Write-Host ("Backup concluído. Perfis exportados: {0}" -f $xmlFiles.Count) -ForegroundColor Green
        foreach ($f in $xmlFiles) {
            Write-Host (" - {0}" -f $f.Name)
        }
        Write-Host ""
        Write-Host "Atenção: os XML contêm as chaves (senhas) em texto claro. Armazene com segurança." -ForegroundColor DarkYellow
    }
}

function Restore-WifiProfiles {
    Write-Host ""
    Write-Host "Restauração de perfis Wi-Fi a partir de XML" -ForegroundColor Cyan
    $folder = Read-Host "Informe a pasta onde estão os arquivos XML do backup"

    if ([string]::IsNullOrWhiteSpace($folder) -or -not (Test-Path -LiteralPath $folder)) {
        Write-Host "Pasta inválida ou não encontrada." -ForegroundColor Red
        return
    }

    $xmlFiles = Get-ChildItem -Path $folder -Filter *.xml -ErrorAction SilentlyContinue
    if (-not $xmlFiles) {
        Write-Host "Nenhum arquivo XML encontrado na pasta especificada." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host ("Foram encontrados {0} arquivo(s) XML." -f $xmlFiles.Count) -ForegroundColor Green
    Write-Host "Os perfis serão importados para o usuário: TODOS (user=all)." -ForegroundColor DarkGray
    Write-Host ""

    foreach ($file in $xmlFiles) {
        Write-Host ("Importando perfil a partir de: {0}" -f $file.Name) -ForegroundColor Cyan
        & netsh wlan add profile filename="$($file.FullName)" user=all | Out-Null
    }

    Write-Host ""
    Write-Host "Restauração concluída. Verifique os perfis com 'netsh wlan show profiles'." -ForegroundColor Green
}

#-------------------- EXCLUSÃO DE PERFIL WI-FI --------------------#

function Remove-WifiProfile {
    Write-Host ""
    $profile = Select-WifiProfile -Titulo "Selecione o perfil Wi-Fi que deseja excluir"
    if (-not $profile) { return }

    Write-Host ""
    Write-Host "Você selecionou o perfil: '$profile'" -ForegroundColor Yellow
    $confirm = Read-Host "Tem certeza que deseja EXCLUIR este perfil? (S/N)"

    if ($confirm -notmatch '^[sSyY]') {
        Write-Host "Operação cancelada pelo usuário." -ForegroundColor Cyan
        return
    }

    Write-Host ""
    Write-Host "Excluindo perfil '$profile'..." -ForegroundColor Cyan

    $out = netsh wlan delete profile name="$profile" 2>&1
    $out | ForEach-Object { Write-Host "   $($_)" }

    $after = Get-WifiProfiles

    if ($after -contains $profile) {
        Write-Host ""
        Write-Host "⚠ O perfil '$profile' ainda aparece na lista após a tentativa de exclusão." -ForegroundColor Yellow
        Write-Host "   Verifique manualmente com: netsh wlan show profiles" -ForegroundColor DarkYellow
    } else {
        Write-Host ""
        Write-Host "✅ Perfil '$profile' excluído da configuração de Wi-Fi (onde existia)." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "Perfis Wi-Fi atuais:" -ForegroundColor Cyan
    Show-WifiList
}

#-------------------- CRIAÇÃO DE NOVO PERFIL WI-FI (XML + NETSH) --------------------#

function New-WifiProfile {
    Write-Host ""
    Write-Host "=== Criação de novo perfil Wi-Fi ===" -ForegroundColor Cyan

    $ssid = Read-Host "Informe o SSID da rede (nome exato do Wi-Fi)"
    if ([string]::IsNullOrWhiteSpace($ssid)) {
        Write-Host "SSID inválido." -ForegroundColor Red
        return
    }

    $existing = Get-WifiProfiles | Where-Object { $_ -eq $ssid }
    if ($existing) {
        Write-Host ""
        Write-Host "⚠ Já existe um perfil com SSID '$ssid' neste equipamento." -ForegroundColor Yellow
        $cont = Read-Host "Deseja continuar e criar/duplicar mesmo assim? (S/N)"
        if ($cont -notmatch '^[sSyY]') {
            Write-Host "Operação cancelada." -ForegroundColor Cyan
            return
        }
    }

    $hiddenAns = Read-Host "A rede é OCULTA (hidden)? (S/N)"
    $nonBroadcast = if ($hiddenAns -match '^[sSyY]') { "true" } else { "false" }

    Write-Host ""
    Write-Host "Tipo de segurança:" -ForegroundColor Cyan
    Write-Host "[1] Aberta (sem autenticação / sem senha)"
    Write-Host "[2] WPA2-Personal (AES, senha pré-compartilhada)"
    $secOpt = Read-Host "Escolha uma opção (1 ou 2)"

    $auth = $null
    $encryption = $null
    $password = $null
    $plainPwd = $null

    switch ($secOpt) {
        "1" {
            $auth = "open"
            $encryption = "none"
        }
        "2" {
            $auth = "WPA2PSK"
            $encryption = "AES"
            $password = Read-Host "Informe a senha (passphrase)" -AsSecureString
            if (-not $password) {
                Write-Host "Senha inválida." -ForegroundColor Red
                return
            }

            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
            $plainPwd = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

            $pwdConfirm = Read-Host "Confirme a senha (digite novamente)"
            if ($plainPwd -ne $pwdConfirm) {
                Write-Host "As senhas não conferem. Operação cancelada." -ForegroundColor Red
                return
            }
        }
        default {
            Write-Host "Opção de segurança inválida." -ForegroundColor Red
            return
        }
    }

    $ssidXml = Escape-Xml -Text $ssid
    $nonBroadcastXml = $nonBroadcast
    $authXml = Escape-Xml -Text $auth
    $encXml  = Escape-Xml -Text $encryption

    $profileXml = $null

    if ($auth -eq "open" -and $encryption -eq "none") {
        $profileXml = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>$ssidXml</name>
    <SSIDConfig>
        <SSID>
            <name>$ssidXml</name>
        </SSID>
        <nonBroadcast>$nonBroadcastXml</nonBroadcast>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>$authXml</authentication>
                <encryption>$encXml</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
        </security>
    </MSM>
</WLANProfile>
"@
    } else {
        $pwdXml = Escape-Xml -Text $plainPwd
        $profileXml = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>$ssidXml</name>
    <SSIDConfig>
        <SSID>
            <name>$ssidXml</name>
        </SSID>
        <nonBroadcast>$nonBroadcastXml</nonBroadcast>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>$authXml</authentication>
                <encryption>$encXml</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>$pwdXml</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>
"@
    }

    $tempPath = [System.IO.Path]::Combine(
        [System.IO.Path]::GetTempPath(),
        ("WiFiProfile_{0}.xml" -f ([Guid]::NewGuid().ToString("N")))
    )
    $profileXml | Out-File -FilePath $tempPath -Encoding UTF8 -Force

    Write-Host ""
    Write-Host "Arquivo de perfil gerado: $tempPath" -ForegroundColor DarkGray
    Write-Host "Importando perfil com netsh..." -ForegroundColor Cyan

    & netsh wlan add profile filename="$tempPath" user=all

    Write-Host ""
    Write-Host "Perfil para SSID '$ssid' criado (ou atualizado) com sucesso, se não houver erros acima." -ForegroundColor Green
    Write-Host "Verifique com: netsh wlan show profiles" -ForegroundColor DarkGray
}

#-------------------- DIAGNÓSTICO DE REDE (PING / TRACERT / ARP) --------------------#

function Run-PingTool {
    Write-Host ""
    $target = Read-Host "Informe o host/IP para ping (ex.: 8.8.8.8 ou www.microsoft.com)"

    if ([string]::IsNullOrWhiteSpace($target)) {
        Write-Host "Destino inválido ou vazio." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "Executando PING em $target ..." -ForegroundColor Cyan
    Write-Host "--------------------------------------------"
    ping $target
    Write-Host "--------------------------------------------"
}

function Run-TracertTool {
    Write-Host ""
    $target = Read-Host "Informe o host/IP para TRACERT (ex.: 8.8.8.8 ou www.microsoft.com)"

    if ([string]::IsNullOrWhiteSpace($target)) {
        Write-Host "Destino inválido ou vazio." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "Executando TRACERT para $target ..." -ForegroundColor Cyan
    Write-Host "--------------------------------------------"
    tracert $target
    Write-Host "--------------------------------------------"
}

function Show-ArpTable {
    Write-Host ""
    $filter = Read-Host "Filtrar por IP (ENTER para mostrar todos)"

    Write-Host ""
    Write-Host "Tabela ARP:" -ForegroundColor Cyan
    Write-Host "--------------------------------------------"

    if ([string]::IsNullOrWhiteSpace($filter)) {
        arp -a
    } else {
        arp -a | Select-String $filter
    }

    Write-Host "--------------------------------------------"
}

function Show-NetworkDiagnosticsMenu {
    $voltar = $false
    do {
        Clear-Host
        Write-Host "========================================="
        Write-Host "         DIAGNÓSTICO DE REDE             "
        Write-Host "========================================="
        Write-Host "[1] Ping"
        Write-Host "[2] Tracert"
        Write-Host "[3] Tabela ARP"
        Write-Host "[0] Voltar ao menu principal"
        Write-Host "========================================="
        $optDiag = Read-Host "Escolha uma opção"

        switch ($optDiag) {
            "1" { Run-PingTool   ; Read-Host "`nPressione ENTER para voltar ao menu de diagnóstico..." | Out-Null }
            "2" { Run-TracertTool; Read-Host "`nPressione ENTER para voltar ao menu de diagnóstico..." | Out-Null }
            "3" { Show-ArpTable  ; Read-Host "`nPressione ENTER para voltar ao menu de diagnóstico..." | Out-Null }
            "0" { $voltar = $true }
            default {
                Write-Host "Opção inválida. Tente novamente." -ForegroundColor Red
                Start-Sleep -Seconds 1.5
            }
        }

    } while (-not $voltar)
}

#-------------------- SCANNER DE REDES WI-FI (SITE SURVEY BÁSICO) --------------------#

function Scan-WifiNetworks {
    Write-Host ""
    Write-Host "Realizando varredura de redes Wi-Fi próximas (site survey básico)..." -ForegroundColor Cyan
    Write-Host "Isso depende do adaptador Wi-Fi estar ligado e habilitado." -ForegroundColor DarkGray
    Write-Host ""

    $output = netsh wlan show networks mode=bssid 2>$null
    if (-not $output) {
        Write-Host "Não foi possível obter a lista de redes. Verifique se o Wi-Fi está ligado." -ForegroundColor Yellow
        return
    }

    $results = @()
    $currentSSID        = $null
    $currentAuth        = $null
    $currentEncryption  = $null
    $currentEntry       = $null

    foreach ($line in $output) {

        if ($line -match "^\s*SSID\s+\d+\s*:\s*(.+)$") {
            if ($currentEntry) {
                $results += [PSCustomObject]$currentEntry
                $currentEntry = $null
            }
            $currentSSID       = $Matches[1].Trim()
            $currentAuth       = $null
            $currentEncryption = $null
            continue
        }

        if ($line -match "^\s*(Authentication|Autenticação)\s*:\s*(.+)$") {
            $currentAuth = $Matches[2].Trim()
            continue
        }

        if ($line -match "^\s*(Encryption|Criptografia)\s*:\s*(.+)$") {
            $currentEncryption = $Matches[2].Trim()
            continue
        }

        if ($line -match "^\s*BSSID\s+\d+\s*:\s*(.+)$") {
            if ($currentEntry) {
                $results += [PSCustomObject]$currentEntry
            }
            $bssid = $Matches[1].Trim()
            $currentEntry = [ordered]@{
                SSID        = $currentSSID
                BSSID       = $bssid
                Signal      = $null
                Channel     = $null
                Banda       = $null
                RadioType   = $null
                Auth        = $currentAuth
                Encryption  = $currentEncryption
            }
            continue
        }

        if ($line -match "^\s*(Signal|Sinal)\s*:\s*(\d+)%") {
            if ($currentEntry) {
                $currentEntry.Signal = [int]$Matches[2]
            }
            continue
        }

        if ($line -match "^\s*(Channel|Canal)\s*:\s*(\d+)") {
            if ($currentEntry) {
                $ch = [int]$Matches[2]
                $currentEntry.Channel = $ch
                $currentEntry.Banda   = Get-WifiBandFromChannel -Channel $ch
            }
            continue
        }

        if ($line -match "^\s*(Radio type|Tipo de rádio)\s*:\s*(.+)$") {
            if ($currentEntry) {
                $currentEntry.RadioType = $Matches[2].Trim()
            }
            continue
        }
    }

    if ($currentEntry) {
        $results += [PSCustomObject]$currentEntry
    }

    if (-not $results -or $results.Count -eq 0) {
        Write-Host "Nenhuma rede encontrada na varredura." -ForegroundColor Yellow
        return
    }

    $results = $results | Sort-Object SSID, BSSID

    Write-Host ""
    Write-Host "=== REDES WI-FI ENCONTRADAS (SITE SURVEY BÁSICO) ===" -ForegroundColor Green

    $ssidAtual = $null
    $idx = 1
    foreach ($item in $results) {
        if ($item.SSID -ne $ssidAtual) {
            Write-Host ""
            Write-Host ("SSID: {0}" -f $item.SSID) -ForegroundColor Cyan
            $ssidAtual = $item.SSID
        }

        Write-Host ("  [{0}] BSSID.....: {1}" -f $idx, $item.BSSID)
        Write-Host ("       Sinal......: {0} %" -f $item.Signal)
        if ($item.Banda) {
            Write-Host ("       Banda......: {0}" -f $item.Banda)
        }
        if ($item.Channel) {
            Write-Host ("       Canal......: {0}" -f $item.Channel)
        }
        if ($item.RadioType) {
            Write-Host ("       Tipo rádio.: {0}" -f $item.RadioType)
        }
        if ($item.Auth) {
            Write-Host ("       Autenticação: {0}" -f $item.Auth)
        }
        if ($item.Encryption) {
            Write-Host ("       Criptografia: {0}" -f $item.Encryption)
        }
        $idx++
    }

    Write-Host ""
    Write-Host "Dica: use esta saída como um mini site survey (interferência, sobreposição de canais, banda, etc.)." -ForegroundColor DarkGray
}

#-------------------- PERFIS WPA-ENTERPRISE + CERTIFICADOS DE CLIENTE --------------------#

function Show-WifiEnterpriseInfo {
    Write-Host ""
    Write-Host "=== Perfis Wi-Fi WPA/WPA2/WPA3 Enterprise + Certificados de Cliente ===" -ForegroundColor Cyan
    Write-Host ""

    # --- Parte 1: Perfis Wi-Fi Enterprise / 802.1X ---
    $profiles = Get-WifiProfiles
    $enterpriseProfiles = @()

    foreach ($p in $profiles) {
        $details = netsh wlan show profile name="$p" 2>$null
        if (-not $details) { continue }

        $authLines  = $details | Select-String "Authentication|Autenticação"
        $encLines   = $details | Select-String "Cipher|Cifra"
        $eapLines   = $details | Select-String "EAP type|Tipo de EAP|Tipo EAP"

        $auth = $null
        if ($authLines) {
            $line  = $authLines[0].ToString()
            $parts = $line.Split(":",2)
            if ($parts.Count -eq 2) { $auth = $parts[1].Trim() }
        }

        $enc = $null
        if ($encLines) {
            $line  = $encLines[0].ToString()
            $parts = $line.Split(":",2)
            if ($parts.Count -eq 2) { $enc = $parts[1].Trim() }
        }

        $eap = $null
        if ($eapLines) {
            $line  = $eapLines[0].ToString()
            $parts = $line.Split(":",2)
            if ($parts.Count -eq 2) { $eap = $parts[1].Trim() }
        }

        $isEnterprise = $false
        if ($auth -match "Enterprise" -or $auth -match "802\.1X" -or $eap) {
            $isEnterprise = $true
        }

        if ($isEnterprise) {
            $enterpriseProfiles += [PSCustomObject]@{
                Perfil        = $p
                Autenticacao  = $auth
                Criptografia  = $enc
                EAP           = $eap
            }
        }
    }

    if ($enterpriseProfiles.Count -gt 0) {
        Write-Host "Perfis Wi-Fi com autenticação Enterprise / 802.1X encontrados:" -ForegroundColor Green
        $i = 1
        foreach ($ep in $enterpriseProfiles) {
            Write-Host ""
            Write-Host ("[{0}] Perfil......: {1}" -f $i, $ep.Perfil) -ForegroundColor Cyan
            Write-Host ("     Autenticação: {0}" -f $ep.Autenticacao)
            if ($ep.Criptografia) {
                Write-Host ("     Criptografia: {0}" -f $ep.Criptografia)
            }
            if ($ep.EAP) {
                Write-Host ("     Tipo EAP....: {0}" -f $ep.EAP)
            } else {
                Write-Host ("     Tipo EAP....: (não informado no perfil)") -ForegroundColor DarkYellow
            }
            $i++
        }
    } else {
        Write-Host "Nenhum perfil Wi-Fi do tipo Enterprise / 802.1X foi encontrado." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "-----------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "Agora procurando certificados de cliente (Client Authentication)" -ForegroundColor Cyan
    Write-Host "nas lojas: Cert:\CurrentUser\My e Cert:\LocalMachine\My..." -ForegroundColor DarkGray
    Write-Host "-----------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""

    # --- Parte 2: Certificados de cliente (Client Authentication) ---
    $stores = @("Cert:\CurrentUser\My", "Cert:\LocalMachine\My")
    $certResults = @()

    foreach ($store in $stores) {
        try {
            $certs = Get-ChildItem -Path $store -ErrorAction Stop
        } catch {
            continue
        }

        foreach ($c in $certs) {
            $isClientAuth = $false
            $ekuFriendly  = @()
            $ekuOid       = @()

            if ($c.EnhancedKeyUsageList) {
                foreach ($eku in $c.EnhancedKeyUsageList) {
                    if ($eku.FriendlyName) { $ekuFriendly += $eku.FriendlyName }
                    if ($eku.ObjectId)     { $ekuOid      += $eku.ObjectId.Value }
                }
            }

            if ($ekuFriendly -contains "Client Authentication" -or
                $ekuFriendly -contains "Autenticação de Cliente") {
                $isClientAuth = $true
            }

            if (-not $isClientAuth -and $ekuOid) {
                if ($ekuOid -contains "1.3.6.1.5.5.7.3.2") {   # OID Client Authentication
                    $isClientAuth = $true
                }
            }

            if ($isClientAuth) {
                $certResults += [PSCustomObject]@{
                    Store      = $store
                    Subject    = $c.Subject
                    Thumbprint = $c.Thumbprint
                    NotAfter   = $c.NotAfter
                    Issuer     = $c.Issuer
                }
            }
        }
    }

    if ($certResults.Count -gt 0) {
        Write-Host "Certificados de cliente encontrados (potencialmente usados em EAP-TLS/802.1X):" -ForegroundColor Green
        $j = 1
        foreach ($cert in $certResults | Sort-Object Store, Subject) {
            Write-Host ""
            Write-Host ("[{0}] Store.....: {1}" -f $j, $cert.Store) -ForegroundColor Cyan
            Write-Host ("     Subject...: {0}" -f $cert.Subject)
            Write-Host ("     Issuer....: {0}" -f $cert.Issuer)
            Write-Host ("     Thumbprint: {0}" -f $cert.Thumbprint)
            Write-Host ("     Válido até: {0}" -f $cert.NotAfter)
            $j++
        }
    } else {
        Write-Host "Nenhum certificado de cliente (Client Authentication) foi encontrado" -ForegroundColor Yellow
        Write-Host "nas lojas CurrentUser\My e LocalMachine\My." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Observação: o Windows não expõe de forma simples qual certificado está" -ForegroundColor DarkGray
    Write-Host "exatamente vinculado a cada perfil Wi-Fi Enterprise. Aqui mostramos:" -ForegroundColor DarkGray
    Write-Host " - Quais perfis são Enterprise / 802.1X" -ForegroundColor DarkGray
    Write-Host " - Quais certificados de cliente existem para autenticação EAP-TLS." -ForegroundColor DarkGray
}

#-------------------- MENU PRINCIPAL --------------------#

$sair = $false
do {
    Clear-Host

    Write-Host "========================================="
    Write-Host "         MENU WI-FI (NETSH)              "
    Write-Host "========================================="
    Write-Host "[1]  Listar redes Wi-Fi neste equipamento"
    Write-Host "[2]  Mostrar a senha das redes Wi-Fi"
    Write-Host "[3]  Características das redes Wi-Fi"
    Write-Host "[4]  Listar adaptadores Wi-Fi (hardware + rede + IP + banda + driver)"
    Write-Host "[5]  Backup de perfis Wi-Fi (exportar XML)"
    Write-Host "[6]  Restaurar perfis Wi-Fi de backup (importar XML)"
    Write-Host "[7]  Excluir um perfil Wi-Fi existente"
    Write-Host "[8]  Diagnóstico de rede (ping / tracert / arp)"
    Write-Host "[9]  Scanner de redes Wi-Fi (site survey básico)"
    Write-Host "[10] Criar novo perfil Wi-Fi (XML + netsh)"
    Write-Host "[11] Ver perfis WPA-Enterprise + certificados de cliente"
    Write-Host "[0]  Sair"
    Write-Host "========================================="
    $opt = Read-Host "Escolha uma opção"

    switch ($opt) {
        "1"  { Show-WifiList           ; Read-Host "`nPressione ENTER para voltar ao menu..." | Out-Null }
        "2"  { Show-WifiPassword       ; Read-Host "`nPressione ENTER para voltar ao menu..." | Out-Null }
        "3"  { Show-WifiCharacteristics; Read-Host "`nPressione ENTER para voltar ao menu..." | Out-Null }
        "4"  { Show-WifiAdapters       ; Read-Host "`nPressione ENTER para voltar ao menu..." | Out-Null }
        "5"  { Backup-WifiProfiles     ; Read-Host "`nPressione ENTER para voltar ao menu..." | Out-Null }
        "6"  { Restore-WifiProfiles    ; Read-Host "`nPressione ENTER para voltar ao menu..." | Out-Null }
        "7"  { Remove-WifiProfile      ; Read-Host "`nPressione ENTER para voltar ao menu..." | Out-Null }
        "8"  { Show-NetworkDiagnosticsMenu }
        "9"  { Scan-WifiNetworks       ; Read-Host "`nPressione ENTER para voltar ao menu..." | Out-Null }
        "10" { New-WifiProfile         ; Read-Host "`nPressione ENTER para voltar ao menu..." | Out-Null }
        "11" { Show-WifiEnterpriseInfo ; Read-Host "`nPressione ENTER para voltar ao menu..." | Out-Null }
        "0"  { $sair = $true }
        default {
            Write-Host "Opção inválida. Tente novamente." -ForegroundColor Red
            Start-Sleep -Seconds 1.5
        }
    }

} while (-not $sair)

Clear-Host
Write-Host "Saindo..." -ForegroundColor Cyan
