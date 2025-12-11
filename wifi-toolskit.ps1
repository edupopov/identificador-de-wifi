<#
.SYNOPSIS
  Utilitário para:
  - Listar redes Wi-Fi
  - Mostrar senhas
  - Mostrar características (WPA/AES etc.)
  - Listar adaptadores Wi-Fi (hardware + rede + IP + banda + driver)
  - Backup/restauração de perfis Wi-Fi (XML)
  - Excluir perfil Wi-Fi específico

.OBS
  - Recomenda-se executar o PowerShell como Administrador.
  - Usa "netsh wlan", Win32_NetworkAdapter, Win32_NetworkAdapterConfiguration,
    Win32_PnPEntity e Win32_PnPSignedDriver.
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

function Get-WifiProfiles {
    # Retorna apenas os nomes dos perfis Wi-Fi (PT-BR e EN)
    $output = netsh wlan show profiles 2>$null
    if (-not $output) {
        return @()
    }

    $profiles = @()

    foreach ($line in $output) {
        if ($line -notmatch ":") { continue }

        $parts = $line.Split(":", 2)
        if ($parts.Count -ne 2) { continue }

        $left  = $parts[0].Trim()
        $right = $parts[1].Trim()
        if (-not $right) { continue }

        # "Todos os Perfis de Usuários" / "All User Profile"
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

#-------------------- Funções de perfis / senhas --------------------#

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
    $senha = $null
    if ($parts.Count -eq 2) {
        $senha = $parts[1].Trim()
    }

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
                if ($channel -ge 1 -and $channel -le 14) {
                    $band = "2.4 GHz"
                } elseif ($channel -ge 32 -and $channel -le 196) {
                    $band = "5 GHz"
                } else {
                    $band = "Desconhecida"
                }
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
            Nome         = $ad.Name
            Conexao      = $ad.NetConnectionID
            MAC          = $mac
            SSID         = $ssid
            BSSID        = $bssid
            Signal       = $signal
            Status       = $status
            Banda        = $band
            Canal        = $channel
            RadioType    = $radioType
            IPv4         = $ipv4
            Subnet       = $subnet
            CIDR         = $cidr
            Gateway      = $gateway
            DNS          = $dnsList
            PNPDeviceID  = $ad.PNPDeviceID
            HardwareID   = $hwId
            DriverName   = $driverName
            DriverVersion= $driverVer
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

    Write-Host "Banda estimada a partir do canal: 1-14 → 2.4 GHz; 32+ → 5 GHz (simplificado)." -ForegroundColor DarkGray
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

#-------------------- MENU PRINCIPAL --------------------#

$sair = $false
do {
    Write-Host ""
    Write-Host "========================================="
    Write-Host "         MENU WI-FI (NETSH)              "
    Write-Host "========================================="
    Write-Host "[1] Listar redes Wi-Fi neste equipamento"
    Write-Host "[2] Mostrar a senha das redes Wi-Fi"
    Write-Host "[3] Características das redes Wi-Fi"
    Write-Host "[4] Listar adaptadores Wi-Fi (hardware + rede + IP + banda + driver)"
    Write-Host "[5] Backup de perfis Wi-Fi (exportar XML)"
    Write-Host "[6] Restaurar perfis Wi-Fi de backup (importar XML)"
    Write-Host "[7] Excluir um perfil Wi-Fi existente"
    Write-Host "[0] Sair"
    Write-Host "========================================="
    $opt = Read-Host "Escolha uma opção"

    switch ($opt) {
        "1" { Show-WifiList }
        "2" { Show-WifiPassword }
        "3" { Show-WifiCharacteristics }
        "4" { Show-WifiAdapters }
        "5" { Backup-WifiProfiles }
        "6" { Restore-WifiProfiles }
        "7" { Remove-WifiProfile }
        "0" { $sair = $true }
        default {
            Write-Host "Opção inválida. Tente novamente." -ForegroundColor Red
        }
    }

} while (-not $sair)

Write-Host "Saindo..." -ForegroundColor Cyan
