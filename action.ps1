#!/usr/bin/env pwsh
param (
    [string] $GitHubRepository = $env:INPUT_GITHUB_REPO,
    [string] $BranchName = $env:INPUT_BRANCH_NAME,
    [String] $ValuesDirectory = $env:INPUT_VALUES_DIRECTORY,
    [String] $SourceBranch = $env:INPUT_SOURCE_BRANCH,
    [String] $YamlPathExpression = $env:INPUT_YAML_PATH_EXPRESSION,
    [String] $Value = $env:INPUT_VALUE,
    [String] $GitHubAppId = $env:INPUT_GITHUB_APP_ID,
    [String] $GitHubAppKey = $env:INPUT_GITHUB_APP_KEY
)

Install-Module -Name powershell-yaml -Scope CurrentUser -Force -Confirm:$False 

function Base64UrlEncodeBytes([Byte[]] $bytes) {
    [Convert]::ToBase64String($bytes) -replace '\+', '-' -replace '/', '_' -replace '='
}
  
function Base64UrlEncodeJson([Object] $object) {
    Base64UrlEncodeBytes([System.Text.Encoding]::UTF8.GetBytes(($object | ConvertTo-Json -Compress)))
}

function Get-GithubAppToken(
    [int] $GitHubAppId,
    [String] $GitHubAppKey,
    [String] $GitHubAppKeyPath
) {
    try {
        # https://docs.github.com/en/developers/apps/building-github-apps/authenticating-with-github-apps
        # https://www.jerriepelser.com/blog/obtain-access-token-github-app-webhook/
        if ($GitHubAppKeyPath) {
            $GitHubAppKey = Get-Content $GitHubAppKeyPath -Raw
        }
        # Remove newline characters and the cert header/footers (-----BEGIN RSA PRIVATE KEY-----)
        $KeyData = ($GitHubAppKey -replace '\n', '') -replace '-+[A-Z ]+-+', ''

        $rsa = [System.Security.Cryptography.RSA]::Create()
        [int]$bytesRead = 0
        $rsa.ImportRSAPrivateKey([Convert]::FromBase64String($KeyData), [ref]$bytesRead)

        $header = Base64UrlEncodeJson(@{alg = 'RS256'; typ = 'JWT' })
        $payload = Base64UrlEncodeJson(@{iat = [DateTimeOffset]::Now.ToUnixTimeSeconds(); exp = [DateTimeOffset]::Now.AddSeconds(600).ToUnixTimeSeconds(); iss = $GitHubAppId })
        $signature = Base64UrlEncodeBytes($rsa.SignData([System.Text.Encoding]::UTF8.GetBytes("$header.$payload"), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1))
        $jwt = "$header.$payload.$signature"

        $headers = @{ Authorization = "Bearer $jwt"; Accept = 'application/vnd.github.machine-man-preview+json' }
        $access_tokens_url = (Invoke-RestMethod -Headers $headers "https://api.github.com/app/installations" -SkipHttpErrorCheck).access_tokens_url
        if (-Not $access_tokens_url) {
            throw "Unable to get GitHub access token url for $GitHubAppId (has GitHubAppKey expired?)"
        }
        $token = (Invoke-RestMethod -Headers $headers -Method Post $access_tokens_url -Verbose:$VerbosePreference).token
        if (-Not $token) {
            throw "Unable to get GitHub access token for $GitHubAppId (has GitHubAppKey expired?)"
        }
        Write-Output $token
    }
    catch {
        Write-Error "GitHubAppId = $GitHubAppId"
        Write-Error "GitHubAppKey = $GitHubAppKey"
        Write-Error $_
        Write-Output ''
    }
}

$token = Get-GithubAppToken -GitHubAppId $GitHubAppId -GitHubAppKey $GitHubAppKey

$repo_dir = Join-Path $env:RUNNER_TEMP '.repo'

$values_file_name = switch -wildcard($SourceBranch) {
    "dev" { "values-dev.yaml" }
    "release" { "values-release.yaml" }
    "release-*" { "values-release.yaml" }
    "main" { "values-main.yaml" }
    "main-review" { "values-main-review.yaml" }
    default { "values-dev.yaml.yaml" }
}
$path = Join-Path $ValuesDirectory $values_file_name

# Get cloneable url with embedded token
$builder = [UriBuilder]::new($GitHubRepository)
$builder.UserName = 'token'
$builder.Password = $token
if (-Not $builder.Path.EndsWith('.git')) {
    $builder.Path = "$($builder.Path).git"
}
$repo_url = $builder.ToString()

git clone $repo_url $repo_dir
if ($LASTEXITCODE -ne 0) { throw "Unable to clone $repo_url to $redo_dir : Exit code is $LASTEXITCODE" }

Push-Location $repo_dir

git checkout $BranchName
if ($LASTEXITCODE -ne 0) { throw "Unable to checkout branch $BranchName : Exit code is $LASTEXITCODE" }

$yqExpression = "$YamlPathExpression = `"`"$Value`"`""
yq -i $yqExpression $path

$status = git status --porcelain
if ($status) {
    git config user.name github-actions
    git config user.email github-actions@github.com
    
    git add -A .
    if ($LASTEXITCODE -ne 0) { throw "Unable to add file to git commit: Exit code is $LASTEXITCODE" }

    git commit -m "Updating $YamlPathExpression to $Value in $Path"
    if ($LASTEXITCODE -ne 0) { throw "Unable to commit: Exit code is $LASTEXITCODE" }

    git push
    if ($LASTEXITCODE -ne 0) { throw "Unable to push commit: Exit code is $LASTEXITCODE" }
}
else {
    Write-Warning "No changes to commit"
}

Pop-Location
