use crate::network::error::{NetworkError, NetworkErrorKind};
use log::info;
use pcap::{Activated, Active, Capture, Device, Offline, State};

pub trait PacketCapture<T>
where
    T: State + Activated,
{
    fn get_capture(self) -> Capture<T>;
    fn apply_filter(&mut self) -> Result<(), NetworkError>;
}

pub struct PacketCaptureGeneric<T>
where
    T: State + Activated,
{
    pub capture: Capture<T>,
    pub filter: Option<String>,
}

impl<T> PacketCaptureGeneric<T>
where
    T: State + Activated,
{
    pub fn open_device_capture(
        device_name: &str,
        filter: Option<String>,
    ) -> Result<PacketCaptureGeneric<Active>, NetworkError> {
        let devices = Device::list()?;
        let target =
            devices
                .into_iter()
                .find(|d| d.name == device_name)
                .ok_or(NetworkError::new(
                    NetworkErrorKind::CaptureError,
                    &format!("Capture device {} not found", device_name),
                ))?;
        info!("Listening on: {:?}", target.name);

        let capture = Capture::from_device(target)?
            .promisc(true)
            .timeout(10000)
            .immediate_mode(true)
            .open()
            .map_err(NetworkError::from)?;

        Ok(PacketCaptureGeneric { capture, filter })
    }

    pub fn open_file_capture(
        file_path: &str,
        filter: Option<String>,
    ) -> Result<PacketCaptureGeneric<Offline>, NetworkError> {
        Ok(PacketCaptureGeneric {
            capture: Capture::from_file(file_path).map_err(NetworkError::from)?,
            filter,
        })
    }
}

impl<T> PacketCapture<T> for PacketCaptureGeneric<T>
where
    T: State + Activated,
{
    fn get_capture(self) -> Capture<T> {
        self.capture
    }
    fn apply_filter(&mut self) -> Result<(), NetworkError> {
        if let Some(filter) = &self.filter {
            info!("Filter applied: {}", filter);
            self.capture.filter(&filter, true)?;
        }
        Ok(())
    }
}
