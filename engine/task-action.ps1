$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [Text.Encoding]::UTF8
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$path = [string]$request.path
$name = [string]$request.name
if (!$name -or $name -match '[\\*?\[\]]' -or $path -match '[*?\[\]]' -or
    !$path.StartsWith('\') -or !$path.EndsWith('\')) { throw 'Invalid task identity' }
$task = Get-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction SilentlyContinue
if ($request.action -eq 'restore') {
    if ($task) { throw 'A task already exists at this location' }
    Register-ScheduledTask -TaskPath $path -TaskName $name -Xml $request.xml | Out-Null
    return
}
if (!$task) { throw 'Task missing. Run a fresh scan.' }
$xml = Export-ScheduledTask -TaskPath $path -TaskName $name
$sha = [Security.Cryptography.SHA256]::Create()
try { $digest = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($xml))).Replace('-', '') }
finally { $sha.Dispose() }
if ($digest -ne $request.digest) { throw 'Task definition changed. Run a fresh scan.' }
switch ($request.action) {
    'disable' { Disable-ScheduledTask -InputObject $task | Out-Null }
    'enable' { Enable-ScheduledTask -InputObject $task | Out-Null }
    'delete' {
        if ($request.xml -cne $xml) { throw 'Backup did not match the live task' }
        if ($xml -match '<LogonType>Password</LogonType>') { throw 'Credential-backed task cannot be safely restored by this app' }
        Unregister-ScheduledTask -InputObject $task -Confirm:$false
    }
    default { throw 'Unknown action' }
}
