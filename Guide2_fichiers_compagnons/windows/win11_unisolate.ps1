# DESISOLE win11. Anti-lockout : rouvrir DETERMINISTE D'ABORD (force OFF, sans dependre d'aucun fichier),
# puis seulement nettoyer regles/backup. L'import du .wfw n'est qu'un confort de restauration EXACTE, jamais critique.
# (Tailscale n'est PAS arrete a l'isolement, donc rien a relancer ici.)
$ErrorActionPreference = "SilentlyContinue"
$dir = "C:\ProgramData\SOAR"
$bk  = "$dir\fw_pre_isolation.wfw"
$st  = "$dir\isolate.status"

# 1) ROUVRIR (deterministe) : etat d'origine = pare-feu OFF. Aucune dependance fichier.
netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound | Out-Null
netsh advfirewall set allprofiles state off | Out-Null
netsh advfirewall firewall set rule name=all new enable=yes | Out-Null

# 2) confort : restauration EXACTE par import, UNIQUEMENT si le pare-feu est deja confirme OFF et le backup present.
$on = (Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq "True" } | Measure-Object).Count
if ($on -eq 0 -and (Test-Path $bk)) {
  netsh advfirewall import "$bk" | Out-Null
  $on2 = (Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq "True" } | Measure-Object).Count
  if ($on2 -ne 0) { netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound | Out-Null; netsh advfirewall set allprofiles state off | Out-Null }
}

# 3) retirer nos regles SOAR (manager + tailscale) + backup
Get-NetFirewallRule -DisplayName "SOAR-ISOLATE-*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Remove-Item $bk -Force -ErrorAction SilentlyContinue

# 4) retirer les taches SOAR (dead-man + tache d'isolement orpheline)
schtasks /delete /tn "SOAR-DEADMAN" /f 2>$null | Out-Null
schtasks /delete /tn "SOAR-ISOLATE-RUN" /f 2>$null | Out-Null
Set-Content -Path $st -Value "UNISOLATED_OK"
