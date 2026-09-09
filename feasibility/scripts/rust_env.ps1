$bitRustBin=[IO.Path]::GetFullPath("$PSScriptRoot\..\.tools\rust\bin")
$bitMingwBin=[IO.Path]::GetFullPath("$PSScriptRoot\..\.tools\llvm-mingw-20250812-msvcrt-x86_64\bin")
$bitLibClang=[IO.Path]::GetFullPath("$PSScriptRoot\..\.tools\python-libclang\clang\native")
$env:PATH="$bitRustBin;$bitMingwBin;"+$env:PATH
$env:CARGO_HOME=[IO.Path]::GetFullPath("$PSScriptRoot\..\.tools\cargo-home")
$env:RUSTC=[IO.Path]::GetFullPath("$PSScriptRoot\..\.tools\rust\bin\rustc.exe")
$env:RUSTFLAGS="-C link-self-contained=yes -C dlltool=$bitMingwBin\llvm-dlltool.exe"
$env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="$bitMingwBin\x86_64-w64-mingw32-gcc.exe"
$env:CC="$bitMingwBin\x86_64-w64-mingw32-clang.exe"
$env:CXX="$bitMingwBin\x86_64-w64-mingw32-clang++.exe"
$env:CXXFLAGS="-isystem $bitMingwBin\..\include\c++\v1"
$env:CXXSTDLIB="c++"
$env:AR="$bitMingwBin\llvm-ar.exe"
$env:LIBCLANG_PATH=$bitLibClang
