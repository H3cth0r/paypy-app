# shell.nix
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  # List of packages required for the development environment
  buildInputs = with pkgs; [
    # --- Node.js / SvelteKit ---
    nodejs_23          # Specific Node.js version (includes npm)
    # nodePackages.npm # Usually included with nodejs_xx, uncomment if needed
    nodePackages.pnpm  # Recommended package manager for modern JS/TS

    # --- Rust / WebAssembly ---
    rustc              # Rust compiler
    cargo              # Rust package manager and build tool
    wasm-pack          # Tool for building Rust-Wasm packages for the web

    clang
    lld

    # --- Optional Build Tools (sometimes needed by Rust build scripts) ---
    # Add these if you encounter build errors related to native dependencies
    # in Rust crates (e.g., crates using C libraries via FFI).
    # pkg-config
    # openssl
    # zlib
    # If on macOS and a crate needs specific SDK frameworks:
    # libiconv # Common macOS dependency
    # darwin.apple_sdk.frameworks.SystemConfiguration
    # darwin.apple_sdk.frameworks.CoreFoundation
    # darwin.apple_sdk.frameworks.Security
  ];

  # Commands to run when entering the Nix shell
  shellHook = ''
    echo "---------------------------------------------"
    echo " SvelteKit + Rust/Wasm Development Shell"
    echo "---------------------------------------------"
    echo "Available tools:"
    # Check command existence before printing version to avoid errors if missing
    [ -x "$(command -v node)" ] && echo " - Node.js $(node --version)"
    [ -x "$(command -v npm)" ] && echo " - npm $(npm --version)"
    [ -x "$(command -v pnpm)" ] && echo " - pnpm $(pnpm --version)"
    [ -x "$(command -v rustc)" ] && echo " - Rustc $(rustc --version)"
    [ -x "$(command -v cargo)" ] && echo " - Cargo $(cargo --version)"
    [ -x "$(command -v wasm-pack)" ] && echo " - wasm-pack $(wasm-pack --version)"
    echo ""
    echo "Local node_modules/.bin added to PATH."
    echo "Ready to develop!"
    echo "---------------------------------------------"

    # Add local node_modules/.bin to PATH for locally installed tools (like vite, svelte-kit)
    export PATH="$PWD/node_modules/.bin:$PATH"

    # Optional: Set Rust environment variables if needed (usually not required)
    # export RUST_BACKTRACE=1
  '';
}
