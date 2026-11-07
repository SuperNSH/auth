//! Single-flight refresh: parallel callers share one in-flight exchange.
//! The first caller drives the HTTP work; the others wait on the same result
//! and each applies it once to the signals.

use crate::error::AuthError;
use crate::session::Session;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

pub(crate) type Work = Pin<Box<dyn Future<Output = Result<Session, AuthError>> + Send>>;

enum FlightState {
    Pending(Vec<Waker>),
    Done(Result<Session, AuthError>),
}

/// One in-flight refresh, shared by every concurrent caller. It carries the
/// refresh token it was started for: a caller may only join a flight of its
/// own token, so a stale flight can never answer for a newer session.
pub(crate) struct RefreshFlight {
    refresh_token: String,
    state: Mutex<FlightState>,
    /// Set when a driver was cancelled mid-flight, so a waiter takes over.
    work: Mutex<Option<Work>>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A panicking holder leaves valid data; a poisoned lock is still usable.
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl RefreshFlight {
    pub(crate) fn start(work: Work, refresh_token: String) -> (Arc<Self>, RefreshFut) {
        let flight = Arc::new(Self {
            refresh_token,
            state: Mutex::new(FlightState::Pending(Vec::new())),
            work: Mutex::new(None),
        });
        let future = RefreshFut::Driver {
            flight: Arc::clone(&flight),
            work: Some(work),
        };
        (flight, future)
    }

    pub(crate) fn join(flight: Arc<Self>) -> RefreshFut {
        RefreshFut::Waiter { flight }
    }

    /// Whether this flight was started for `refresh_token`.
    pub(crate) fn is_for(&self, refresh_token: &str) -> bool {
        self.refresh_token == refresh_token
    }

    fn finish(&self, result: Result<Session, AuthError>) {
        let waiters = {
            let mut state = lock(&self.state);
            match std::mem::replace(&mut *state, FlightState::Done(result)) {
                FlightState::Pending(waiters) => waiters,
                FlightState::Done(_) => Vec::new(),
            }
        };
        for waiter in waiters {
            waiter.wake();
        }
    }
}

pub(crate) enum RefreshFut {
    Driver {
        flight: Arc<RefreshFlight>,
        work: Option<Work>,
    },
    Waiter {
        flight: Arc<RefreshFlight>,
    },
}

impl RefreshFut {
    fn poll_driver(
        flight: &Arc<RefreshFlight>,
        work: &mut Option<Work>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Session, AuthError>> {
        let Some(pending) = work.as_mut() else {
            // Finished on an earlier poll; the answer is in the flight.
            return match &*lock(&flight.state) {
                FlightState::Done(result) => Poll::Ready(result.clone()),
                FlightState::Pending(_) => Poll::Pending,
            };
        };
        match pending.as_mut().poll(cx) {
            Poll::Ready(result) => {
                *work = None;
                flight.finish(result.clone());
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Future for RefreshFut {
    type Output = Result<Session, AuthError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            match this {
                RefreshFut::Driver { flight, work } => {
                    return Self::poll_driver(flight, work, cx);
                }
                RefreshFut::Waiter { flight } => {
                    // One lock covers both the Done check and the waker
                    // registration: a finish() that runs in between must
                    // still find this waiter's waker and wake it. Checking
                    // and registering in separate locks would let a finish
                    // slip through and leave the waiter pending forever.
                    let abandoned = {
                        let mut state = lock(&flight.state);
                        match &mut *state {
                            FlightState::Done(result) => return Poll::Ready(result.clone()),
                            FlightState::Pending(waiters) => {
                                waiters.retain(|w| !w.will_wake(cx.waker()));
                                waiters.push(cx.waker().clone());
                            }
                        }
                        drop(state);
                        lock(&flight.work).take()
                    };
                    if let Some(work) = abandoned {
                        // A cancelled driver's work: this waiter drives it.
                        // Its registered waker becomes a harmless self-wake
                        // when the flight finishes.
                        *this = RefreshFut::Driver {
                            flight: Arc::clone(flight),
                            work: Some(work),
                        };
                        continue;
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}

impl Drop for RefreshFut {
    fn drop(&mut self) {
        // A cancelled driver hands unfinished work back and wakes a waiter.
        if let RefreshFut::Driver { flight, work } = self
            && let Some(work) = work.take()
        {
            *lock(&flight.work) = Some(work);
            let waiters = match &mut *lock(&flight.state) {
                FlightState::Pending(waiters) => std::mem::take(waiters),
                FlightState::Done(_) => Vec::new(),
            };
            for waiter in waiters {
                waiter.wake();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::ProviderId;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Wake;

    fn session(access_token: &str) -> Session {
        Session {
            provider: ProviderId::Mock,
            access_token: access_token.to_owned(),
            refresh_token: Some("rt-1".to_owned()),
            id_token: None,
            expires_at: 0,
            scope: String::new(),
        }
    }

    /// A waker that records being woken.
    struct Flag(AtomicBool);

    impl Wake for Flag {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn a_registered_waiter_is_woken_and_answered_by_finish() {
        let (flight, _driver) =
            RefreshFlight::start(Box::pin(async { Ok(session("at-1")) }), "rt-1".to_owned());
        let flag = Arc::new(Flag(AtomicBool::new(false)));
        let waker = Waker::from(Arc::clone(&flag));
        let mut cx = Context::from_waker(&waker);
        let mut waiter = RefreshFlight::join(flight);
        assert!(Pin::new(&mut waiter).poll(&mut cx).is_pending());
        assert!(!flag.0.load(Ordering::SeqCst));
        // The driver finishing later must reach the already-registered waiter.
        waiter.flight_for_test().finish(Ok(session("at-1")));
        assert!(flag.0.load(Ordering::SeqCst), "finish() must wake waiters");
        assert!(matches!(
            Pin::new(&mut waiter).poll(&mut cx),
            Poll::Ready(Ok(_))
        ));
    }

    #[test]
    fn a_cancelled_drivers_work_is_taken_over_by_a_waiter() {
        let (flight, driver) =
            RefreshFlight::start(Box::pin(async { Ok(session("at-1")) }), "rt-1".to_owned());
        // Dropping the undriven driver puts the work back for a waiter.
        drop(driver);
        let mut waiter = RefreshFlight::join(flight);
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert!(matches!(
            Pin::new(&mut waiter).poll(&mut cx),
            Poll::Ready(Ok(_))
        ));
    }

    #[test]
    fn a_flight_belongs_to_one_refresh_token() {
        let (flight, _driver) =
            RefreshFlight::start(Box::pin(async { Ok(session("at-1")) }), "rt-1".to_owned());
        assert!(flight.is_for("rt-1"));
        assert!(!flight.is_for("rt-9"));
    }

    impl RefreshFut {
        // Tests reach the flight they hold; production code never needs it.
        fn flight_for_test(&mut self) -> Arc<RefreshFlight> {
            match self {
                RefreshFut::Driver { flight, .. } | RefreshFut::Waiter { flight } => {
                    Arc::clone(flight)
                }
            }
        }
    }
}
