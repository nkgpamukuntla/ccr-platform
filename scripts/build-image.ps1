<#
Builds the linux/arm64 image in AWS CodeBuild from the committed HEAD (no Docker needed
locally) and prints the tag to deploy.

  .\scripts\build-image.ps1 -Environment dev [-Profile edr-dev]

Only committed code is built (git archive), so nothing untracked or ignored leaves the laptop.
Deploy afterwards from the infra repo: write the tag into infra/envs/<env>.image, plan, apply.
#>
param(
    [string]$Environment = "dev",
    [string]$Profile = "edr-dev",
    [string]$Region = "us-east-1"
)
$ErrorActionPreference = "Stop"
$env:AWS_PROFILE = $Profile
$root = Split-Path $PSScriptRoot -Parent
Push-Location $root
try {
    if (git status --porcelain) { Write-Warning "Uncommitted changes are NOT included; building HEAD." }
    $tag = (git rev-parse --short=12 HEAD).Trim()
    $account = (aws sts get-caller-identity --query Account --output text).Trim()
    $bucket = "ec-$Environment-build-src-$account"
    $project = "ec-$Environment-app-build"
    $zip = Join-Path ([IO.Path]::GetTempPath()) "ccr-$tag.zip"

    git archive --format=zip -o $zip HEAD
    aws s3 cp $zip "s3://$bucket/src/$tag.zip" --only-show-errors
    Remove-Item $zip

    $id = aws codebuild start-build --project-name $project `
        --source-location-override "$bucket/src/$tag.zip" `
        --environment-variables-override "name=IMAGE_TAG,value=$tag,type=PLAINTEXT" `
        --query build.id --output text
    Write-Host "CodeBuild $id building $tag ..."
    do {
        Start-Sleep -Seconds 15
        $status = aws codebuild batch-get-builds --ids $id --query "builds[0].buildStatus" --output text
        Write-Host "  $status"
    } while ($status -eq "IN_PROGRESS")
    if ($status -ne "SUCCEEDED") {
        throw "Build $status. Logs: aws logs tail /aws/codebuild/$project --since 30m"
    }
    Write-Host "Image ready: $tag"
    $tag
}
finally {
    Pop-Location
}
