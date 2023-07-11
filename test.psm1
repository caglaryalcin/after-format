Write-Host "Installing Microsoft Visual Studio Code Extensions..." -NoNewline
    
    $docker = "eamodio.gitlens","davidanson.vscode-markdownlint"
    $autocomplete = "formulahendry.auto-close-tag","formulahendry.auto-rename-tag","formulahendry.auto-complete-tag","streetsidesoftware.code-spell-checker"
    $design = "pkief.material-icon-theme"
    $vspowershell = "ms-vscode.powershell","tobysmith568.run-in-powershell"
    $frontend = "emin.vscode-react-native-kit","msjsdiag.vscode-react-native","pranaygp.vscode-css-peek","rodrigovallades.es7-react-js-snippets","dsznajder.es7-react-js-snippets","dbaeumer.vscode-eslint","christian-kohler.path-intellisense","esbenp.prettier-vscode"
    $github = "github.vscode-pull-request-github","github.copilot"
    $extensions = $docker + $autocomplete + $design + $vspowershell + $frontend + $github

$cmd = "code --list-extensions"
Invoke-Expression $cmd -OutVariable output | Out-Null
$installed = $output -split "\s"

foreach ($ext in $extensions) {
    if ($installed.Contains($ext)) {
        Write-Host $ext "already installed." -ForegroundColor Gray
    } else {
        
        code --install-extension $ext
    }
}