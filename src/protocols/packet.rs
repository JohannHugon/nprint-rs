use core::fmt::Debug;

/// A trait to provide a generic handling of protocols
///
/// Types implementing `Protocol` are expected to provide mechanisms
/// for constructing an instance from a byte slice, retrieving parsed
/// float data, and accessing header metadata.
///
pub(crate) trait PacketHeader: Debug {
    /// Initializes a new instance, and return it.
    ///
    /// # Arguments
    /// * `data` - A byte slice containing the raw packet.
    fn new(data: &[u8]) -> Self
    where
        Self: Sized;

    /// Returns a reference to a vector of 32-bit floating-point numbers representing the
    /// parsed data content from the protocol if not possible, may return a default representation.
    fn get_data(&self) -> &Vec<f32>;

    /// Returns the list of all field names of the protocols.
    fn get_headers() -> Vec<String>
    where
        Self: Sized;
}
