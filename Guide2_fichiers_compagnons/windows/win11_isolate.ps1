# ISOLE win11 (execute en SYSTEM via tache planifiee = detache de la session SSH).
# Coupe TOUT (Internet + LAN + Tailscale, in+out, IPv4+IPv6) SAUF le manager (Wazuh 1514/1515/55000 + SSH 22).
# Tailscale : le service est laisse RUNNING (PAS de 'tailscale down') mais AUCUNE exception -> son trafic est bloque par le pare-feu comme le reste ; il se reconnecte seul au desisolement.
# ANTI-LOCKOUT : tout est construit pendant que le pare-feu est OFF ; l'ACTIVATION ('state on') est faite EN DERNIER
# (donc jamais d'instant ON+block sans regle SSH). Rollback/desisolement forcent 'state off' sans dependre du .wfw. sshd force Automatic.
$ErrorActionPreference = "SilentlyContinue"
$dir = "C:\ProgramData\SOAR"; New-Item -ItemType Directory -Force -Path $dir | Out-Null
$bk  = "$dir\fw_pre_isolation.wfw"
$st  = "$dir\isolate.status"
$mgr = "192.168.0.1"
$tsExe = "C:\Program Files\Tailscale\tailscaled.exe"
Set-Content -Path $st -Value "RUNNING"

function Add-SoarRules {
  Get-NetFirewallRule -DisplayName "SOAR-ISOLATE-*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
  # exceptions MANAGER : SSH de secours + lien Wazuh (par IP du manager)
  netsh advfirewall firewall add rule name="SOAR-ISOLATE-SSH-IN"  dir=in  action=allow protocol=TCP localport=22 remoteip=$mgr profile=any | Out-Null
  netsh advfirewall firewall add rule name="SOAR-ISOLATE-SSH-OUT" dir=out action=allow protocol=TCP localport=22 remoteip=$mgr profile=any | Out-Null
  netsh advfirewall firewall add rule name="SOAR-ISOLATE-WZ-OUT"  dir=out action=allow protocol=TCP remoteport=1514,1515,55000 remoteip=$mgr profile=any | Out-Null
  netsh advfirewall firewall add rule name="SOAR-ISOLATE-WZ-IN"   dir=in  action=allow protocol=TCP localport=1514,1515,55000 remoteip=$mgr profile=any | Out-Null
  # PAS d'exception Tailscale : son trafic (underlay + overlay) est bloque par la policy par defaut comme tout le reste.
}
function Force-Open {   # rouvrir DETERMINISTE, sans dependre d'aucun fichier (etat d'origine = pare-feu OFF)
  netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound | Out-Null
  netsh advfirewall set allprofiles state off | Out-Null
  netsh advfirewall firewall set rule name=all new enable=yes | Out-Null
  Get-NetFirewallRule -DisplayName "SOAR-ISOLATE-*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
}

# 1) backup non-clobber AVANT toute modif : seulement si pas deja un backup ET pas deja isole (sinon on figerait l'etat isole)
$already = Get-NetFirewallRule -DisplayName "SOAR-ISOLATE-*" -ErrorAction SilentlyContinue
if ((-not (Test-Path $bk)) -and (-not $already)) { netsh advfirewall export "$bk" | Out-Null }

# 2) idempotence + anti-fenetre : garantir le pare-feu OFF avant de (re)construire (annule une isolation precedente)
netsh advfirewall set allprofiles state off | Out-Null

# 3) sshd doit redemarrer tout seul apres un reboot pendant l'isolement (sinon plus de voie de secours)
Set-Service sshd -StartupType Automatic; Start-Service sshd

# 4) Tailscale : service laisse RUNNING (pas de 'tailscale down'), mais aucune exception pare-feu -> trafic coupe comme le reste ; reconnexion auto au desisolement.

# 5) CONSTRUIRE l'isolement PENDANT que le pare-feu est OFF (aucune coupure SSH possible ici)
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound | Out-Null   # policy par defaut (appliquee seulement quand ON)
netsh advfirewall firewall set rule name=all new enable=no | Out-Null                     # neutralise toutes les regles allow built-in (DNS/IPv6/LAN/OpenSSH-any...)
Add-SoarRules                                                                              # exceptions manager (SSH + Wazuh) + Tailscale, Enabled

# 6) ACTIVER LE PARE-FEU EN DERNIER : a cet instant les exceptions SSH/Wazuh/Tailscale sont deja en place
netsh advfirewall set allprofiles state on | Out-Null

# 7) verif robuste de la voie de secours manager ; sinon ROLLBACK SUR (Force-Open ; backup conserve)
$sshSvc    = Get-Service sshd -ErrorAction SilentlyContinue
$sshListen = Get-NetTCPConnection -State Listen -LocalPort 22 -ErrorAction SilentlyContinue
$sshIn = Get-NetFirewallRule -DisplayName "SOAR-ISOLATE-SSH-IN" -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq "True" }
$wzOut = Get-NetFirewallRule -DisplayName "SOAR-ISOLATE-WZ-OUT" -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq "True" }
$blocked = (Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq "True" -and $_.DefaultInboundAction -eq "Block" -and $_.DefaultOutboundAction -eq "Block" } | Measure-Object).Count
if (($sshSvc.Status -eq "Running") -and $sshListen -and $sshIn -and $wzOut -and $blocked -ge 1) {
  Set-Content -Path $st -Value "ISOLATED_OK"
} else {
  Force-Open
  Set-Content -Path $st -Value "ROLLBACK"
}
