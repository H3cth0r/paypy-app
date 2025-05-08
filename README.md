# paypy-app


## Preview
```
npm run build
npm run preview -- --host
```

## Cargo/Rust setup
```
cargo install wasm-pack
```

```
cargo new --lib paypy-wasm
cd paypy-wasm

wasm-pack build --target web

```

Copy pkg directory to svelte `src/lib/pkg`

Install the local package:
```
npm install ./src/lib/pkg
```

