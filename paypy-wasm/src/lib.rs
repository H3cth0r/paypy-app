use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Calculator {
    value: i32,
}

#[wasm_bindgen]
impl Calculator {
    pub fn new() -> Calculator {
        Calculator { value: 0 }
    }

    pub fn add(&mut self, n: i32) -> i32 {
        self.value += n;
        self.value
    }

    #[wasm_bindgen]
    pub fn greet(name: &str) -> String {
        format!("Hello, {}!", name)
    }
}
