use core::fmt::Debug;

pub(crate) trait Protocol: Debug {
    fn new(data: &[u8]) -> Self
    where
        Self: Sized;
    fn get_data(&self) -> &Vec<f32>;
    #[allow(dead_code)]
    fn get_headers() -> Vec<String>
    where
        Self: Sized;
}
