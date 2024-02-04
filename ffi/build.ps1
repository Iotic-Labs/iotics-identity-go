# Set the name of your Go program
$programName = "lib-iotics-id-sdk"

# Set the source file name (assuming it's in the same directory as the script)
$sourceFile = "."

# Set the output directory for compiled binaries
$outputDirectory = ".\lib"

$env:GOARCH="amd64"
$env:CGO_ENABLED=1

# Compile for Windows
Write-Host "Compiling for Windows..."
$env:GOOS="windows"
go build -x -v -buildmode=c-shared -o "$outputDirectory\$programName.win.dll" $sourceFile

if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Compilation for Windows failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host "Compilation completed successfully."