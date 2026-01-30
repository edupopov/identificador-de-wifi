<#
.SYNOPSIS
  Toolkit de Wi‑Fi e Rede (PowerShell 5.1 compatível).

.DESCRIPTION
  Utilitário interativo para:
   - Listar redes Wi‑Fi (perfis do Windows)
   - Mostrar senhas e características (WPA/AES etc.)
   - Inventário de adaptadores Wi‑Fi (hardware + IP + banda + driver)
   - Backup/restore de perfis Wi‑Fi (XML via netsh)
   - Remover perfil específico
   - Diagnóstico de rede (ping / tracert / ARP)
   - Scanner de redes Wi‑Fi (site survey com netsh)
   - Criar novo perfil Wi‑Fi (gera XML + importa via netsh)
   - Perfis Enterprise + Certificados de cliente (EAP‑TLS)
   - Status de VPN e análise de rota padrão (Full vs Split)

.NOTES
  - Desenvolvido para Windows PowerShell 5.1 (sem operadores do PS7).
  - Requer netsh e módulos padrão do Windows (CIM/WMI, NetTCPIP).
#>

# Garantir saída UTF-8 (não quebra se indisponível)
try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new() } catch {}

# =========================
#  FUNÇÕES AUXILIARES
# =========================

function Get-CIDRFromMask {
<#
.SYNOPSIS
  Converte máscara IPv4 (255.255.255.0) em /CIDR (24).
.PARAMETER Mask
  Máscara IPv4 em notação decimal pontuada.
#>
    param([Parameter(Mandatory)][string] $Mask)
    if (-not $Mask) { return $null }
    $octets = $Mask.Split('.'); if ($octets.Count -ne 4) { return $null }
    $bits = 0
    foreach ($octet in $octets) {
        [int]$n = 0
        if (-not [int]::TryParse($octet, [ref]$n)) { return $null }
        while ($n -gt 0) { $bits += ($n -band 1); $n = $n -shr 1 }
    }
    return $bits
}

function Get-WifiBandFromChannel {
<#
.SYNOPSIS
  Deduz a banda (2.4/5/6 GHz) a partir do canal.
.PARAMETER Channel
  Número do canal.
#>
    param([Parameter(Mandatory)][int] $Channel)
    if     ($Channel -ge 1  -and $Channel -le 14)  { "2.4 GHz" }
    elseif ($Channel -ge 32 -and $Channel -le 196) { "5 GHz" }
    elseif ($Channel -gt 196)                      { "6 GHz / Outra" }
    else                                           { "Desconhecida" }
}

function ConvertTo-XmlEscaped {
<#
.SYNOPSIS
  Escapa texto para uso em XML (caracteres especiais).
.PARAMETER Text
  Texto de entrada.
#>
    param([string] $Text)
    if ($null -eq $Text) { return "" }
    $t = $Text
    $t = $t -replace '&', '&amp;'
    $t = $t -replace '<', '&lt;'
    $t = $t -replace '>', '&gt;'
    $t = $t -replace '"','&quot;'
    $t = $t -replace "'",'&apos;'
    return $t
}

function Get-WifiProfiles {
<#
.SYNOPSIS
  Retorna lista de perfis Wi‑Fi (SSIDs) salvos no Windows.
#>
    $output = netsh wlan show profiles 2>$null
    if (-not $output) { return @() }

    $profiles = @()
    foreach ($line in $output) {
        if ($line -notmatch ":") { continue }
        $parts = $line.Split(":", 2); if ($parts.Count -ne 2) { continue }
        $left  = $parts[0].Trim()
        $right = $parts[1].Trim()
        if (-not $right) { continue }
        if ($left -match "Perfi" -or $left -match "Profile") { $profiles += $right }
    }
    return ($profiles | Sort-Object -Unique)
}

function Select-WifiProfile {
<#
.SYNOPSIS
  Exibe lista de perfis Wi‑Fi e retorna o SSID escolhido.
.PARAMETER Titulo
  Título opcional a mostrar no prompt.
#>
    param([string] $Titulo = "Selecione uma rede Wi‑Fi:")
    $profiles = Get-WifiProfiles
    if (-not $profiles) { Write-Host "Nenhuma rede Wi‑Fi encontrada." -ForegroundColor Yellow; return $null }

    Write-Host ""
    Write-Host "=== $Titulo ===" -ForegroundColor Cyan
    for ($i=0; $i -lt $profiles.Count; $i++) { Write-Host ("[{0}] {1}" -f ($i+1), $profiles[$i]) }
    Write-Host "[0] Voltar"

    $choice = Read-Host "Digite o número"
    if ($choice -eq "0" -or [string]::IsNullOrWhiteSpace($choice)) { return $null }

    [int]$index = 0
    if (-not [int]::TryParse($choice, [ref]$index)) { Write-Host "Opção inválida." -ForegroundColor Red; return $null }
    $index--
    if ($index -lt 0 -or $index -ge $profiles.Count) { Write-Host "Opção fora da faixa." -ForegroundColor Red; return $null }

    return $profiles[$index]
}

# =========================
#  PERFIS / SENHAS
# =========================

function Show-WifiPassword {
<#
.SYNOPSIS
  Mostra a senha (PSK) de um perfil Wi‑Fi (quando aplicável).
#>
    $wifiProfile = Select-WifiProfile -Titulo "Selecione a rede para exibir a senha"
    if (-not $wifiProfile) { return }

    Write-Host "`nObtendo dados da rede '$wifiProfile'..." -ForegroundColor Cyan
    $details = netsh wlan show profile name="$wifiProfile" key=clear 2>$null
    if (-not $details) { Write-Host "Não foi possível obter detalhes." -ForegroundColor Red; return }

    $keyLine = $details | Where-Object { $_ -match 'Key Content' -or $_ -match 'Conteúdo.*Chave' -or $_ -match 'Conteudo.*Chave' } | Select-Object -First 1
    Write-Host ""
    Write-Host "=== SENHA DA REDE '$wifiProfile' ===" -ForegroundColor Green
    if ($keyLine) {
        $parts = $keyLine.ToString().Split(":",2)
        $pwd = if ($parts.Count -eq 2) { $parts[1].Trim() } else { $null }
        if ($pwd) { Write-Host "Senha: $pwd" } else { Write-Host "Senha não encontrada." -ForegroundColor Yellow }
    } else {
        Write-Host "Senha não encontrada (perfil sem PSK/Enterprise ou sem permissão)." -ForegroundColor Yellow
    }
}

function Show-WifiCharacteristics {
<#
.SYNOPSIS
  Exibe autenticação e cifragem de um perfil Wi‑Fi.
#>
    $wifiProfile = Select-WifiProfile -Titulo "Selecione a rede para características"
    if (-not $wifiProfile) { return }

    Write-Host "`nObtendo características da rede '$wifiProfile'..." -ForegroundColor Cyan
    $details = netsh wlan show profile name="$wifiProfile" key=clear 2>$null
    if (-not $details) { Write-Host "Não foi possível obter detalhes." -ForegroundColor Red; return }

    $auth  = $details | Select-String "Authentication|Autenticação" | ForEach-Object { $_.ToString().Split(":",2)[1].Trim() } | Sort-Object -Unique
    $cipher= $details | Select-String "Cipher|Cifra"               | ForEach-Object { $_.ToString().Split(":",2)[1].Trim() } | Sort-Object -Unique

    Write-Host ""
    Write-Host "=== CARACTERÍSTICAS DA REDE '$wifiProfile' ===" -ForegroundColor Green
    Write-Host ("Autenticação: {0}" -f ($auth -join ", "))
    Write-Host ("Criptografia: {0}" -f ($cipher -join ", "))
    Write-Host ""
}

function Show-WifiList {
<#
.SYNOPSIS
  Lista os perfis Wi‑Fi configurados no Windows.
#>
    $profiles = Get-WifiProfiles
    if (-not $profiles) { Write-Host "Nenhuma rede Wi‑Fi encontrada." -ForegroundColor Yellow; return }
    Write-Host "`n=== Redes Wi‑Fi neste equipamento ===" -ForegroundColor Green
    $i=1; foreach ($p in $profiles) { Write-Host ("[{0}] {1}" -f $i,$p); $i++ }; Write-Host ""
}

# =========================
#  INTERFACES / ADAPTADORES
# =========================

function Get-WifiInterfaces {
<#
.SYNOPSIS
  Extrai dados do 'netsh wlan show interfaces' (SSID, BSSID, Sinal, Canal...).
#>
    $output = netsh wlan show interfaces 2>$null
    if (-not $output) { return @() }
    $interfaces=@(); $current=[ordered]@{}

    foreach ($line in $output) {
        if ($line -match "^\s*(Name|Nome)\s*:\s*(.+)$") {
            if ($current.Contains("Name")) { $interfaces += [PSCustomObject]$current; $current=[ordered]@{} }
            $current.Name = $Matches[2].Trim(); continue
        }
        if ($line -match "^\s*SSID\s*:\s*(.+)$")       { $current.SSID   = $Matches[1].Trim(); continue }
        if ($line -match "^\s*BSSID\s*:\s*(.+)$")      { $current.BSSID  = $Matches[1].Trim(); continue }
        if ($line -match "^\s*(Signal|Sinal)\s*:\s*(\d+)%") { $current.SignalPercent=[int]$Matches[2]; continue }
        if ($line -match "^\s*(Channel|Canal)\s*:\s*(\d+)") { $current.Channel=[int]$Matches[2]; continue }
        if ($line -match "^\s*(Radio type|Tipo de rádio)\s*:\s*(.+)$") { $current.RadioType=$Matches[2].Trim(); continue }
    }
    if ($current.Contains("Name")) { $interfaces += [PSCustomObject]$current }
    return $interfaces
}

function Show-WifiAdapters {
<#
.SYNOPSIS
  Mostra inventário detalhado de adaptadores Wi‑Fi (hardware + IP + banda + driver).
#>
    Write-Host "`nObtendo adaptadores Wi‑Fi..." -ForegroundColor Cyan

    $adapters = Get-CimInstance Win32_NetworkAdapter -ErrorAction SilentlyContinue |
      Where-Object {
        $_.NetEnabled -eq $true -and (
            $_.Name -match "Wireless|Wi-?Fi|802\.11" -or
            $_.Description -match "Wireless|Wi-?Fi|802\.11" -or
            $_.NetConnectionID -match "Wi-?Fi|Wireless"
        )
      }

    if (-not $adapters) { Write-Host "Nenhum adaptador Wi‑Fi encontrado." -ForegroundColor Yellow; return }

    $wifiIfaces = Get-WifiInterfaces
    $ipConfigs  = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" -ErrorAction SilentlyContinue
    $result=@()

    foreach ($ad in $adapters) {
        $mac=$ad.MACAddress
        $status = switch ($ad.NetConnectionStatus) { 2 { "Conectado" } 7 { "Desconectado" } default { "Status:$($_)" } }

        $iface = if ($ad.NetConnectionID) { $wifiIfaces | Where-Object { $_.Name -eq $ad.NetConnectionID } | Select-Object -First 1 }
        $ssid=$null;$bssid=$null;$signal=0;$channel=$null;$radioType=$null;$band=$null
        if ($iface) { $ssid=$iface.SSID; $bssid=$iface.BSSID; $signal=$iface.SignalPercent; $channel=$iface.Channel; $radioType=$iface.RadioType; if ($channel) { $band=Get-WifiBandFromChannel $channel } }
        if (-not $ssid) { $ssid="(não conectado)" }

        $cfg = if ($mac) { $ipConfigs | Where-Object { $_.MACAddress -eq $mac } | Select-Object -First 1 }

        $ipv4=$null;$subnet=$null;$gateway=$null;$dnsList=$null;$cidr=$null
        if ($cfg) {
            if ($cfg.IPAddress)         { $ipv4   = ($cfg.IPAddress | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -First 1) }
            if ($cfg.IPSubnet)          { $subnet = ($cfg.IPSubnet  | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -First 1) }
            if ($cfg.DefaultIPGateway)  { $gateway= ($cfg.DefaultIPGateway | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -First 1) }
            if ($cfg.DNSServerSearchOrder) { $dnsList = $cfg.DNSServerSearchOrder -join ", " }
            if ($subnet) { $cidr = Get-CIDRFromMask -Mask $subnet }
        }

        $pnp = Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | Where-Object { $_.DeviceID -eq $ad.PNPDeviceID } | Select-Object -First 1
        $hwEnt = Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.DeviceID -eq $ad.PNPDeviceID } | Select-Object -First 1
        $hwId = if ($hwEnt -and $hwEnt.HardwareID) { ($hwEnt.HardwareID | Select-Object -First 2) -join " | " }
        $driverName=$pnp.DriverName; $driverVer=$pnp.DriverVersion

        $result += [PSCustomObject]@{
            Nome=$ad.Name; Conexao=$ad.NetConnectionID; MAC=$mac; SSID=$ssid; BSSID=$bssid; Signal=$signal; Status=$status
            Banda=$band; Canal=$channel; RadioType=$radioType
            IPv4=$ipv4; Subnet=$subnet; CIDR=$cidr; Gateway=$gateway; DNS=$dnsList
            PNPDeviceID=$ad.PNPDeviceID; HardwareID=$hwId; DriverName=$driverName; DriverVersion=$driverVer
        }
    }

    Write-Host "`n=== ADAPTADORES WI‑FI ENCONTRADOS ===" -ForegroundColor Green
    $index=1
    foreach ($item in $result) {
        Write-Host ("[{0}] {1}" -f $index, $item.Nome) -ForegroundColor Cyan
        Write-Host ("    Conexão......: {0}" -f $item.Conexao)
        Write-Host ("    MAC..........: {0}" -f $item.MAC)
        Write-Host ("    SSID.........: {0}" -f $item.SSID)
        if ($item.BSSID)   { Write-Host ("    BSSID........: {0}" -f $item.BSSID) }
        Write-Host ("    Força sinal..: {0} %" -f $item.Signal)
        Write-Host ("    Status.......: {0}" -f $item.Status)
        if ($item.Banda)   { Write-Host ("    Banda........: {0}" -f $item.Banda) }
        if ($item.Canal)   { Write-Host ("    Canal........: {0}" -f $item.Canal) }
        if ($item.RadioType) { Write-Host ("    Tipo rádio...: {0}" -f $item.RadioType) }

        if ($item.IPv4) {
            $cidrStr = if ($item.CIDR) { " /$($item.CIDR)" } else { "" }
            Write-Host ("    IPv4.........: {0}" -f $item.IPv4)
            if ($item.Subnet)  { Write-Host ("    Máscara......: {0}{1}" -f $item.Subnet, $cidrStr) }
            if ($item.Gateway) { Write-Host ("    Gateway......: {0}" -f $item.Gateway) }
            if ($item.DNS)     { Write-Host ("    DNS..........: {0}" -f $item.DNS) }
        } else {
            Write-Host ("    IPv4.........: (sem IP configurado)") -ForegroundColor DarkYellow
        }

        if ($item.DriverName -or $item.DriverVersion) {
            Write-Host ("    Driver.......: {0} {1}" -f $item.DriverName, $item.DriverVersion)
        }
        if ($item.HardwareID) { Write-Host ("    HardwareID...: {0}" -f $item.HardwareID) }
        Write-Host ("    PNPDeviceID..: {0}" -f $item.PNPDeviceID) -ForegroundColor DarkGray
        Write-Host ""
        $index++
    }

    Write-Host "Banda por canal: 1–14→2.4 GHz; 32–196→5 GHz; >196→6 GHz/Outra." -ForegroundColor DarkGray
    Write-Host "CIDR calculado a partir da máscara IPv4." -ForegroundColor DarkGray
}

# =========================
#  BACKUP / RESTAURAÇÃO
# =========================

function Backup-WifiProfiles {
<#
.SYNOPSIS
  Exporta todos os perfis Wi‑Fi (XML) com senha (key=clear).
.NOTES
  Os XML conterão senhas em texto claro → guarde com segurança.
#>
    Write-Host ""
    $defaultFolder = Join-Path $env:USERPROFILE ("Desktop\WiFiBackup_" + (Get-Date -Format 'yyyyMMdd_HHmmss'))
    Write-Host "Backup de perfis Wi‑Fi (netsh export key=clear)" -ForegroundColor Cyan
    Write-Host "Pasta sugerida: $defaultFolder"
    $folder = Read-Host "Informe a pasta de destino (ENTER para usar a sugerida)"
    if ([string]::IsNullOrWhiteSpace($folder)) { $folder=$defaultFolder }
    if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }

    Write-Host "`nExportando para: $folder" -ForegroundColor Green
    netsh wlan export profile key=clear folder="$folder" | Out-Null

    $xmlFiles = Get-ChildItem -Path $folder -Filter *.xml -ErrorAction SilentlyContinue
    if (-not $xmlFiles) {
        Write-Host "Nenhum XML gerado." -ForegroundColor Yellow
    } else {
        Write-Host ("Backup concluído. Perfis exportados: {0}" -f $xmlFiles.Count) -ForegroundColor Green
        foreach ($f in $xmlFiles) { Write-Host (" - {0}" -f $f.Name) }
        Write-Host "`nAtenção: os XML contêm chaves em texto claro." -ForegroundColor DarkYellow
    }
}

function Restore-WifiProfiles {
<#
.SYNOPSIS
  Restaura perfis Wi‑Fi a partir de XML exportado.
#>
    Write-Host "`nRestauração de perfis Wi‑Fi (XML)" -ForegroundColor Cyan
    $folder = Read-Host "Informe a pasta com os arquivos XML"
    if ([string]::IsNullOrWhiteSpace($folder) -or -not (Test-Path -LiteralPath $folder)) { Write-Host "Pasta inválida." -ForegroundColor Red; return }

    $xmlFiles = Get-ChildItem -Path $folder -Filter *.xml -ErrorAction SilentlyContinue
    if (-not $xmlFiles) { Write-Host "Nenhum XML encontrado." -ForegroundColor Yellow; return }

    Write-Host ("Foram encontrados {0} arquivo(s) XML." -f $xmlFiles.Count) -ForegroundColor Green
    foreach ($file in $xmlFiles) {
        Write-Host ("Importando: {0}" -f $file.Name) -ForegroundColor Cyan
        netsh wlan add profile filename="$($file.FullName)" user=all | Out-Null
    }
    Write-Host "`nRestauração concluída." -ForegroundColor Green
}

# =========================
#  EXCLUSÃO DE PERFIL
# =========================

function Remove-WifiProfile {
<#
.SYNOPSIS
  Remove um perfil Wi‑Fi selecionado.
#>
    Write-Host ""
    $selectedWifiProfile = Select-WifiProfile -Titulo "Selecione o perfil Wi‑Fi para excluir"
    if (-not $selectedWifiProfile) { return }

    Write-Host "`nVocê selecionou: '$selectedWifiProfile'" -ForegroundColor Yellow
    $confirm = Read-Host "Confirmar EXCLUSÃO? (S/N)"
    if ($confirm -notmatch '^[sSyY]') { Write-Host "Cancelado." -ForegroundColor Cyan; return }

    Write-Host "Excluindo..." -ForegroundColor Cyan
    $out = netsh wlan delete profile name="$selectedWifiProfile" 2>&1
    $out | ForEach-Object { Write-Host "   $_" }

    $after = Get-WifiProfiles
    if ($after -contains $selectedWifiProfile) { Write-Host "⚠ Perfil ainda listado." -ForegroundColor Yellow }
    else { Write-Host "✅ Perfil removido." -ForegroundColor Green }

    Write-Host "`nPerfis atuais:" -ForegroundColor Cyan
    Show-WifiList
}

# =========================
#  CRIAÇÃO DE NOVO PERFIL
# =========================

function New-WifiProfile {
<#
.SYNOPSIS
  Cria novo perfil Wi‑Fi (XML) e importa via netsh.
.DESCRIPTION
  Implementa: Aberta (open/none) e WPA2‑PSK (AES).
#>
    Write-Host "`n=== Criação de novo perfil Wi‑Fi ===" -ForegroundColor Cyan

    $ssid = Read-Host "Informe o SSID (nome exato)"
    if ([string]::IsNullOrWhiteSpace($ssid)) { Write-Host "SSID inválido." -ForegroundColor Red; return }

    $exists = Get-WifiProfiles | Where-Object { $_ -eq $ssid }
    if ($exists) {
        Write-Host "⚠ Já existe um perfil com SSID '$ssid'." -ForegroundColor Yellow
        $cont = Read-Host "Continuar? (S/N)"
        if ($cont -notmatch '^[sSyY]') { Write-Host "Cancelado." -ForegroundColor Cyan; return }
    }

    $nonBroadcast = if ((Read-Host "A rede é OCULTA (hidden)? (S/N)") -match '^[sSyY]') { "true" } else { "false" }

    Write-Host "`nTipo de segurança:" -ForegroundColor Cyan
    Write-Host "[1] Aberta (sem senha)"
    Write-Host "[2] WPA2-Personal (AES, PSK)"
    $secOpt = Read-Host "Escolha (1/2)"

    $auth=$null; $encryption=$null; $plainPwd=$null
    switch ($secOpt) {
        "1" { $auth="open";  $encryption="none" }
        "2" {
            $auth="WPA2PSK"; $encryption="AES"
            $secure = Read-Host "Senha (passphrase)" -AsSecureString
            if (-not $secure) { Write-Host "Senha inválida." -ForegroundColor Red; return }
            $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            $plainPwd = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            if ($plainPwd -ne (Read-Host "Confirme a senha")) { Write-Host "Senhas não conferem." -ForegroundColor Red; return }
        }
        default { Write-Host "Opção inválida." -ForegroundColor Red; return }
    }

    $ssidXml  = ConvertTo-XmlEscaped -Text $ssid
    $authXml  = ConvertTo-XmlEscaped -Text $auth
    $encXml   = ConvertTo-XmlEscaped -Text $encryption

    if ($auth -eq "open" -and $encryption -eq "none") {
        $profileXml = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>$ssidXml</name>
  <SSIDConfig>
    <SSID><name>$ssidXml</name></SSID>
    <nonBroadcast>$nonBroadcast</nonBroadcast>
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
        $pwdXml = ConvertTo-XmlEscaped -Text $plainPwd
        $profileXml = @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>$ssidXml</name>
  <SSIDConfig>
    <SSID><name>$ssidXml</name></SSID>
    <nonBroadcast>$nonBroadcast</nonBroadcast>
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

    $tempPath = [IO.Path]::Combine([IO.Path]::GetTempPath(), ("WiFiProfile_{0}.xml" -f ([Guid]::NewGuid().ToString("N"))))
    $profileXml | Out-File -FilePath $tempPath -Encoding UTF8 -Force
    Write-Host "`nArquivo gerado: $tempPath" -ForegroundColor DarkGray
    Write-Host "Importando com netsh..." -ForegroundColor Cyan
    netsh wlan add profile filename="$tempPath" user=all
    Write-Host "`nPerfil '$ssid' criado/atualizado." -ForegroundColor Green
}

# =========================
#  DIAGNÓSTICO DE REDE
# =========================

function Invoke-PingTool {
<#
.SYNOPSIS
  Wrapper simples para ping.
#>
    Write-Host ""
    $target = Read-Host "Host/IP para ping (ex.: 8.8.8.8)"
    if ([string]::IsNullOrWhiteSpace($target)) { Write-Host "Destino inválido." -ForegroundColor Yellow; return }
    Write-Host "`n------ PING $target ------"; ping $target; Write-Host "--------------------------"
}

function Invoke-TracertTool {
<#
.SYNOPSIS
  Wrapper simples para tracert.
#>
    Write-Host ""
    $target = Read-Host "Host/IP para tracert (ex.: 8.8.8.8)"
    if ([string]::IsNullOrWhiteSpace($target)) { Write-Host "Destino inválido." -ForegroundColor Yellow; return }
    Write-Host "`n---- TRACERT $target ----"; tracert $target; Write-Host "--------------------------"
}

function Show-ArpTable {
<#
.SYNOPSIS
  Mostra a tabela ARP, com filtro opcional.
#>
    Write-Host ""
    $filter = Read-Host "Filtrar por IP (ENTER para todos)"
    Write-Host "`nTabela ARP:`n--------------------------"
    if ([string]::IsNullOrWhiteSpace($filter)) { arp -a } else { arp -a | Select-String $filter }
    Write-Host "--------------------------"
}

function Show-NetworkDiagnosticsMenu {
<#
.SYNOPSIS
  Submenu de diagnóstico (ping/tracert/arp).
#>
    $voltar=$false
    do {
        Clear-Host
        Write-Host "========================================="
        Write-Host "         DIAGNÓSTICO DE REDE             "
        Write-Host "========================================="
        Write-Host "[1] Ping"
        Write-Host "[2] Tracert"
        Write-Host "[3] Tabela ARP"
        Write-Host "[0] Voltar"
        $optDiag = Read-Host "Escolha"

        switch ($optDiag) {
            "1" { Invoke-PingTool    ; Read-Host "`nENTER para voltar..." | Out-Null }
            "2" { Invoke-TracertTool ; Read-Host "`nENTER para voltar..." | Out-Null }
            "3" { Show-ArpTable      ; Read-Host "`nENTER para voltar..." | Out-Null }
            "0" { $voltar = $true }
            default { Write-Host "Opção inválida." -ForegroundColor Red; Start-Sleep 1 }
        }
    } while (-not $voltar)
}

# =========================
#  SITE SURVEY (NETSH)
# =========================

function Get-WifiNetworksSurvey {
<#
.SYNOPSIS
  Scanner de redes Wi‑Fi próximas (site survey básico).
#>
    Write-Host "`nVarredura de redes Wi‑Fi..." -ForegroundColor Cyan
    $output = netsh wlan show networks mode=bssid 2>$null
    if (-not $output) { Write-Host "Falha ao listar redes. Verifique se o Wi‑Fi está ligado." -ForegroundColor Yellow; return }

    $results=@(); $currentSSID=$null; $currentAuth=$null; $currentEncryption=$null; $currentEntry=$null
    foreach ($line in $output) {
        if ($line -match "^\s*SSID\s+\d+\s*:\s*(.+)$") { if ($currentEntry){$results += [PSCustomObject]$currentEntry; $currentEntry=$null}; $currentSSID=$Matches[1].Trim(); $currentAuth=$null; $currentEncryption=$null; continue }
        if ($line -match "^\s*(Authentication|Autenticação)\s*:\s*(.+)$") { $currentAuth=$Matches[2].Trim(); continue }
        if ($line -match "^\s*(Encryption|Criptografia)\s*:\s*(.+)$")     { $currentEncryption=$Matches[2].Trim(); continue }
        if ($line -match "^\s*BSSID\s+\d+\s*:\s*(.+)$") {
            if ($currentEntry) { $results += [PSCustomObject]$currentEntry }
            $currentEntry=[ordered]@{ SSID=$currentSSID; BSSID=$Matches[1].Trim(); Signal=$null; Channel=$null; Banda=$null; RadioType=$null; Auth=$currentAuth; Encryption=$currentEncryption }
            continue
        }
        if ($line -match "^\s*(Signal|Sinal)\s*:\s*(\d+)%") { if ($currentEntry){$currentEntry.Signal=[int]$Matches[2]}; continue }
        if ($line -match "^\s*(Channel|Canal)\s*:\s*(\d+)") { if ($currentEntry){ $ch=[int]$Matches[2]; $currentEntry.Channel=$ch; $currentEntry.Banda=Get-WifiBandFromChannel $ch }; continue }
        if ($line -match "^\s*(Radio type|Tipo de rádio)\s*:\s*(.+)$") { if ($currentEntry){$currentEntry.RadioType=$Matches[2].Trim()} ; continue }
    }
    if ($currentEntry) { $results += [PSCustomObject]$currentEntry }
    if (-not $results) { Write-Host "Nenhuma rede encontrada." -ForegroundColor Yellow; return }

    $results = $results | Sort-Object SSID, BSSID
    Write-Host "`n=== REDES WI‑FI ENCONTRADAS ===" -ForegroundColor Green
    $ssidAtual=$null; $idx=1
    foreach ($item in $results) {
        if ($item.SSID -ne $ssidAtual) { Write-Host ""; Write-Host ("SSID: {0}" -f $item.SSID) -ForegroundColor Cyan; $ssidAtual=$item.SSID }
        Write-Host ("  [{0}] BSSID.....: {1}" -f $idx,$item.BSSID)
        Write-Host ("       Sinal......: {0} %" -f $item.Signal)
        if ($item.Banda)     { Write-Host ("       Banda......: {0}" -f $item.Banda) }
        if ($item.Channel)   { Write-Host ("       Canal......: {0}" -f $item.Channel) }
        if ($item.RadioType) { Write-Host ("       Tipo rádio.: {0}" -f $item.RadioType) }
        if ($item.Auth)      { Write-Host ("       Autenticação: {0}" -f $item.Auth) }
        if ($item.Encryption){ Write-Host ("       Criptografia: {0}" -f $item.Encryption) }
        $idx++
    }
    Write-Host "`nDica: use para avaliar sinal e sobreposição de canais." -ForegroundColor DarkGray
}

# =========================
#  ENTERPRISE + CERTIFICADOS
# =========================

function Show-WifiEnterpriseInfo {
<#
.SYNOPSIS
  Lista perfis Enterprise/802.1X e certificados de Cliente (EAP‑TLS).
#>
    Write-Host "`n=== Perfis Enterprise + Certificados de Cliente ===" -ForegroundColor Cyan

    $profiles = Get-WifiProfiles
    $enterpriseProfiles=@()

    foreach ($p in $profiles) {
        $details = netsh wlan show profile name="$p" 2>$null
        if (-not $details) { continue }

        $authLines = $details | Select-String "Authentication|Autenticação"
        $encLines  = $details | Select-String "Cipher|Cifra"
        $eapLines  = $details | Select-String "EAP type|Tipo de EAP|Tipo EAP"

        $auth = if ($authLines) { $authLines[0].ToString().Split(":",2)[1].Trim() }
        $enc  = if ($encLines)  { $encLines[0].ToString().Split(":",2)[1].Trim() }
        $eap  = if ($eapLines)  { $eapLines[0].ToString().Split(":",2)[1].Trim() }

        $isEnterprise = ($auth -match "Enterprise" -or $auth -match "802\.1X" -or $eap)
        if ($isEnterprise) { $enterpriseProfiles += [PSCustomObject]@{ Perfil=$p; Autenticacao=$auth; Criptografia=$enc; EAP=$eap } }
    }

    if ($enterpriseProfiles) {
        Write-Host "Perfis Enterprise/802.1X:" -ForegroundColor Green
        $i=1; foreach ($ep in $enterpriseProfiles) {
            Write-Host ""
            Write-Host ("[{0}] Perfil......: {1}" -f $i,$ep.Perfil) -ForegroundColor Cyan
            Write-Host ("     Autenticação: {0}" -f $ep.Autenticacao)
            if ($ep.Criptografia) { Write-Host ("     Criptografia: {0}" -f $ep.Criptografia) }
            if ($ep.EAP) { Write-Host ("     Tipo EAP....: {0}" -f $ep.EAP) } else { Write-Host ("     Tipo EAP....: (não informado)") -ForegroundColor DarkYellow }
            $i++
        }
    } else { Write-Host "Nenhum perfil Enterprise encontrado." -ForegroundColor Yellow }

    Write-Host "`nProcurando certificados de Cliente (EKU 1.3.6.1.5.5.7.3.2) nas lojas CurrentUser\My e LocalMachine\My..."
    $stores = @("Cert:\CurrentUser\My","Cert:\LocalMachine\My")
    $certResults=@(); $now=Get-Date

    foreach ($store in $stores) {
        try { $certs = Get-ChildItem -Path $store -ErrorAction Stop } catch { continue }
        foreach ($c in $certs) {
            $ekuFriendly=@(); $ekuOid=@()
            if ($c.EnhancedKeyUsageList) {
                foreach ($eku in $c.EnhancedKeyUsageList) {
                    if ($eku.FriendlyName) { $ekuFriendly += $eku.FriendlyName }
                    if ($eku.ObjectId)     { $ekuOid      += $eku.ObjectId.Value }
                }
            }
            $isClientAuth = ($ekuFriendly -contains "Client Authentication" -or
                             $ekuFriendly -contains "Autenticação de Cliente" -or
                             $ekuOid -contains "1.3.6.1.5.5.7.3.2")
            if ($isClientAuth) {
                $keySize=$null; try { if ($c.PublicKey -and $c.PublicKey.Key) { $keySize = $c.PublicKey.Key.KeySize } } catch {}
                $sigAlg = if ($c.SignatureAlgorithm -and $c.SignatureAlgorithm.FriendlyName) { $c.SignatureAlgorithm.FriendlyName }
                $certResults += [PSCustomObject]@{
                    Store=$store; Subject=$c.Subject; FriendlyName=$c.FriendlyName; Thumbprint=$c.Thumbprint
                    SerialNumber=$c.SerialNumber; NotBefore=$c.NotBefore; NotAfter=$c.NotAfter
                    IsValidNow=($c.NotBefore -le $now -and $c.NotAfter -ge $now)
                    Issuer=$c.Issuer; KeySize=$keySize; SignatureAlg=$sigAlg
                    EKU_Friendly=($ekuFriendly -join ", "); EKU_Oid=($ekuOid -join ", ")
                }
            }
        }
    }

    if ($certResults) {
        Write-Host "`nCertificados de Cliente:" -ForegroundColor Green
        $j=1; foreach ($cert in $certResults | Sort-Object Store,Subject) {
            $val = if ($cert.IsValidNow) { "Sim" } else { "Não" }
            Write-Host ""
            Write-Host ("[{0}] Store.........: {1}" -f $j,$cert.Store) -ForegroundColor Cyan
            if ($cert.FriendlyName) { Write-Host ("     Friendly Name..: {0}" -f $cert.FriendlyName) }
            Write-Host ("     Subject.......: {0}" -f $cert.Subject)
            Write-Host ("     Issuer........: {0}" -f $cert.Issuer)
            Write-Host ("     Serial........: {0}" -f $cert.SerialNumber)
            Write-Host ("     Thumbprint....: {0}" -f $cert.Thumbprint)
            Write-Host ("     Válido de/até.: {0} / {1}" -f $cert.NotBefore,$cert.NotAfter)
            Write-Host ("     Válido agora?.: {0}" -f $val)
            if ($cert.KeySize)  { Write-Host ("     Chave.........: {0} bits" -f $cert.KeySize) }
            if ($cert.SignatureAlg) { Write-Host ("     Assinatura....: {0}" -f $cert.SignatureAlg) }
            if ($cert.EKU_Friendly) { Write-Host ("     EKU...........: {0}" -f $cert.EKU_Friendly) }
            if ($cert.EKU_Oid)  { Write-Host ("     EKU OIDs......: {0}" -f $cert.EKU_Oid) }
            $j++
        }
    } else { Write-Host "Nenhum certificado de Cliente encontrado." -ForegroundColor Yellow }

    Write-Host "`nObs.: Windows não mapeia facilmente perfil Enterprise ↔ certificado; use estas listas para correlação." -ForegroundColor DarkGray
}

# =========================
#  ROTAS PADRÃO (FULL/SPLIT)
# =========================

function Show-VpnDefaultRouteAnalysis {
<#
.SYNOPSIS
  Analisa rotas 0.0.0.0/0 (IPv4) e infere Full vs Split tunnel.
#>
    Write-Host "`n=== ANÁLISE DE ROTAS PADRÃO (VPN x LAN) ===" -ForegroundColor Cyan

    if (-not (Get-Command Get-NetRoute -ErrorAction SilentlyContinue)) {
        Write-Host "Get-NetRoute indisponível neste sistema." -ForegroundColor Red; return
    }

    $defaultRoutes = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if (-not $defaultRoutes) { Write-Host "Nenhuma rota padrão IPv4 encontrada." -ForegroundColor Yellow; return }

    $vpnPattern = 'Fortinet|Forti|OpenVPN|TAP-Windows|TAP-WIN32|TAP-Windows Adapter|Cisco AnyConnect|AnyConnect|WireGuard|Checkpoint|Check Point|SonicWall|GlobalProtect|VPN'
    $routeInfo=@()

    foreach ($r in $defaultRoutes) {
        $adapter = Get-NetAdapter -InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue
        $alias = $null; $desc=$null; $status=$null; $mac=$null
        if ($adapter) { $alias=$adapter.Name; $desc=$adapter.InterfaceDescription; $status=$adapter.Status; $mac=$adapter.MacAddress }

        $texto = ""
        if ($alias) { $texto += "$alias " }
        if ($desc)  { $texto += "$desc " }

        $tipoInterface = "Genérica/Virtual"
        if ($texto -match $vpnPattern)            { $tipoInterface = "Provável VPN de terceiros" }
        elseif ($desc -and $desc -match "Wi-?Fi|Wireless|802\.11") { $tipoInterface = "Wi‑Fi" }
        elseif ($desc -and $desc -match "Ethernet")               { $tipoInterface = "Ethernet" }

        $routeInfo += [PSCustomObject]@{
            DestinationPrefix=$r.DestinationPrefix
            InterfaceIndex=$r.InterfaceIndex
            InterfaceAlias=$alias
            Description=$desc
            Status=$status
            MacAddress=$mac
            NextHop=$r.NextHop
            RouteMetric=$r.RouteMetric
            InterfaceMetric=$r.InterfaceMetric
            EffectiveMetric=($r.RouteMetric + $r.InterfaceMetric)
            TipoInterface=$tipoInterface
            EhVpnTerceiro=($texto -match $vpnPattern)
        }
    }

    Write-Host "Rotas padrão IPv4:" -ForegroundColor Green
    $routeInfo | Sort-Object EffectiveMetric | Format-Table DestinationPrefix,InterfaceIndex,InterfaceAlias,Status,NextHop,RouteMetric,InterfaceMetric,EffectiveMetric -AutoSize

    Write-Host "`nDetalhes por interface:" -ForegroundColor Green
    $idx=1
    foreach ($ri in $routeInfo | Sort-Object EffectiveMetric) {

        # Substituições compatíveis com PS 5.1 (sem '??')
        $aliasText = if ([string]::IsNullOrWhiteSpace($ri.InterfaceAlias)) { "(sem alias)" } else { $ri.InterfaceAlias }
        $descText  = if ([string]::IsNullOrWhiteSpace($ri.Description))    { "(sem descrição)" } else { $ri.Description }
        $statusTxt = if ($ri.Status) { $ri.Status } else { "(desconhecido)" }
        $gwText    = if ([string]::IsNullOrWhiteSpace($ri.NextHop))        { "(sem gateway)" } else { $ri.NextHop }
        $vpnTxt    = if ($ri.EhVpnTerceiro) { "Sim" } else { "Não" }

        Write-Host ("[{0}] IfIndex......: {1}" -f $idx,$ri.InterfaceIndex) -ForegroundColor Cyan
        Write-Host ("     Alias........: {0}" -f $aliasText)
        Write-Host ("     Descrição....: {0}" -f $descText)
        Write-Host ("     Status.......: {0}" -f $statusTxt)
        if ($ri.MacAddress) { Write-Host ("     MAC..........: {0}" -f $ri.MacAddress) }
        Write-Host ("     Gateway......: {0}" -f $gwText)
        Write-Host ("     Métrica rota.: {0}" -f $ri.RouteMetric)
        Write-Host ("     Métrica iface: {0}" -f $ri.InterfaceMetric)
        Write-Host ("     Métrica efet.: {0}" -f $ri.EffectiveMetric)
        Write-Host ("     Tipo.........: {0}" -f $ri.TipoInterface)
        Write-Host ("     HeurísticaVPN: {0}" -f $vpnTxt)
        Write-Host ""
        $idx++
    }

    $ativo = $routeInfo | Where-Object { $_.Status -eq "Up" } | Sort-Object EffectiveMetric | Select-Object -First 1
    $vpnUp = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" -and (($_.Name+" "+$_.InterfaceDescription) -match $vpnPattern) }

    Write-Host "========================================="
    Write-Host "Resumo:" -ForegroundColor Cyan
    if ($vpnUp) { Write-Host ("VPN de terceiros 'Up': {0}" -f (($vpnUp | Select-Object -Expand Name) -join ", ")) }
    else { Write-Host "Sem VPN de terceiros 'Up'." -ForegroundColor Yellow }

    if ($ativo) {
        if ($ativo.EhVpnTerceiro) { Write-Host "→ CENÁRIO: VPN FULL TUNNEL (rota padrão via VPN)." -ForegroundColor Green }
        elseif ($vpnUp)           { Write-Host "→ CENÁRIO: VPN ATIVA EM SPLIT TUNNEL (rota padrão via LAN/Wi‑Fi)." -ForegroundColor Yellow }
        else                      { Write-Host "→ CENÁRIO: Sem VPN ativa; rota padrão via LAN/Wi‑Fi." -ForegroundColor Yellow }
    } else {
        Write-Host "Nenhuma interface com rota padrão está 'Up'." -ForegroundColor Yellow
    }
}

# =========================
#  MENU PRINCIPAL
# =========================

$sair = $false
do {
    Clear-Host
    Write-Host "========================================="
    Write-Host "         MENU WI‑FI (NETSH)              "
    Write-Host "========================================="
    Write-Host "[1]  Listar redes Wi‑Fi (perfis salvos)"
    Write-Host "[2]  Mostrar senha de um perfil Wi‑Fi"
    Write-Host "[3]  Características de um perfil (auth/cifra)"
    Write-Host "[4]  Adaptadores Wi‑Fi (HW + IP + banda + driver)"
    Write-Host "[5]  Backup de perfis (XML com senha)"
    Write-Host "[6]  Restaurar perfis (importar XML)"
    Write-Host "[7]  Excluir um perfil Wi‑Fi"
    Write-Host "[8]  Diagnóstico de rede (ping / tracert / arp)"
    Write-Host "[9]  Scanner de redes Wi‑Fi (site survey)"
    Write-Host "[10] Criar novo perfil Wi‑Fi (XML + netsh)"
    Write-Host "[11] Perfis Enterprise + Certificados (cliente)"
    Write-Host "[12] Status de VPN"
    Write-Host "[13] Análise de rotas padrão (Full/Split VPN)"
    Write-Host "[0]  Sair"
    Write-Host "========================================="

    $opt = Read-Host "Escolha uma opção"
    switch ($opt) {
        "1"  { Show-WifiList               ; Read-Host "`nENTER para voltar..." | Out-Null }
        "2"  { Show-WifiPassword           ; Read-Host "`nENTER para voltar..." | Out-Null }
        "3"  { Show-WifiCharacteristics    ; Read-Host "`nENTER para voltar..." | Out-Null }
        "4"  { Show-WifiAdapters           ; Read-Host "`nENTER para voltar..." | Out-Null }
        "5"  { Backup-WifiProfiles         ; Read-Host "`nENTER para voltar..." | Out-Null }
        "6"  { Restore-WifiProfiles        ; Read-Host "`nENTER para voltar..." | Out-Null }
        "7"  { Remove-WifiProfile          ; Read-Host "`nENTER para voltar..." | Out-Null }
        "8"  { Show-NetworkDiagnosticsMenu }
        "9"  { Get-WifiNetworksSurvey      ; Read-Host "`nENTER para voltar..." | Out-Null }
        "10" { New-WifiProfile             ; Read-Host "`nENTER para voltar..." | Out-Null }
        "11" { Show-WifiEnterpriseInfo     ; Read-Host "`nENTER para voltar..." | Out-Null }
        "12" { Show-VpnStatus              ; Read-Host "`nENTER para voltar..." | Out-Null }
        "13" { Show-VpnDefaultRouteAnalysis; Read-Host "`nENTER para voltar..." | Out-Null }
        "0"  { $sair = $true }
        default { Write-Host "Opção inválida." -ForegroundColor Red; Start-Sleep 1.5 }
    }
} while (-not $sair)

Clear-Host
Write-Host "Saindo..." -ForegroundColor Cyan
