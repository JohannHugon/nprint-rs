use core::fmt::Debug;

/// A trait to provide a generic handling of protocols 
///
/// Types implementing `Protocol` are expected to provide mechanisms
/// for constructing an instance from a byte slice, retrieving parsed
/// float data, and accessing header metadata.
///
pub trait Protocol: Debug {
    /// Initiate the new instance of the protocols
    ///
    /// # Arguments
    /// * `data` - A byte slice containing the raw packet.
    ///
    /// # Returns
    /// An instance of the implementing protocol.
    fn new(data: &[u8]) -> Self
    where
        Self: Sized;
    /// Returns a reference to the vector of parsed packet.
    ///
    /// # Returns
    /// A reference to a vector of 32-bit floating-point numbers representing the
    /// parsed data content from the protocol.
    fn get_data(&self) -> &Vec<f32>;
    /// Returns the name list of all field of the protocols.
    ///
    ///
    /// # Returns
    /// A vector of strings, each representing a field of the protocol's header.
    fn get_headers() -> Vec<String>
    where
        Self: Sized;
}
