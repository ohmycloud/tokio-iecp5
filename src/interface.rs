use std::time::Duration;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use tokio::{select, time::sleep};

use crate::{error::Error, frame::asdu::Asdu};

pub trait Connect {
    async fn send_timeout(&self, asdu: Asdu, timeout: Option<Duration>) -> Result<(), Error>;
    async fn send(&self, asdu: Asdu) -> Result<(), Error>;
    // TODO: wait for ack
    // async fn send(&self, asdu: Asdu) -> Result<oneshot>;
}

pub struct TestConn {
    want: Bytes,
    sleep_time: Option<Duration>,
}

impl TestConn {
    pub fn new(want: Bytes, timeout: Option<Duration>) -> TestConn {
        TestConn {
            want,
            sleep_time: timeout,
        }
    }
}

impl Connect for TestConn {
    async fn send_timeout(&self, asdu: Asdu, timeout: Option<Duration>) -> Result<(), Error> {
        let mut timeout_timer = sleep(Duration::MAX);
        if let Some(duration) = timeout {
            timeout_timer = sleep(duration);
        }

        select! {
            r = self.send(asdu) => { r }
            _ = timeout_timer => {
                Err(anyhow!("Timeout"))?
            }
        }
    }

    async fn send(&self, asdu: Asdu) -> Result<(), Error> {
        if let Some(sleep_time) = self.sleep_time {
            sleep(sleep_time).await;
        }

        let out: Bytes = asdu.try_into().unwrap();
        if out != self.want {
            return Err(anyhow!("Send() out = {:?}, want = {:?}", out, self.want))?;
        }
        Ok(())
    }
}
