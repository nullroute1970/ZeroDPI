//! Delayed packet injections belong to their interceptor generation.

use std::thread::JoinHandle;
use zerodpi_core::interceptor::InterceptorShutdown;

pub(crate) struct EmissionWorkers {
    shutdown: InterceptorShutdown,
    workers: Vec<JoinHandle<()>>,
}

impl EmissionWorkers {
    pub fn new(shutdown: InterceptorShutdown) -> Self {
        Self {
            shutdown,
            workers: Vec::new(),
        }
    }

    pub fn push(&mut self, worker: JoinHandle<()>) {
        let mut index = 0;
        while index < self.workers.len() {
            if self.workers[index].is_finished() {
                let _ = self.workers.swap_remove(index).join();
            } else {
                index += 1;
            }
        }
        self.workers.push(worker);
    }

    pub fn finish(&mut self) {
        self.shutdown.request();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

impl Drop for EmissionWorkers {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn dropping_the_interceptor_cancels_and_joins_delayed_injections() {
        let shutdown = InterceptorShutdown::default();
        let finished = Arc::new(AtomicBool::new(false));
        let worker_finished = finished.clone();
        let worker_shutdown = shutdown.clone();
        let mut emissions = EmissionWorkers::new(shutdown.clone());
        emissions.push(std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while !worker_shutdown.is_requested() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
            // Stand in for closing a raw socket / native injection handle.
            worker_finished.store(true, Ordering::SeqCst);
        }));
        drop(emissions);
        assert!(shutdown.is_requested());
        assert!(finished.load(Ordering::SeqCst));
    }
}
