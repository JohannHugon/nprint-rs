extern crate nprint_rs;

use nprint_rs::hello_world;

#[cfg(test)] 
mod tests {
    use super::*;
    #[test]
    fn test_hello_world() {
        let result = hello_world();
        assert_eq!(result, "hello_world");
    }
}
