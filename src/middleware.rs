use once_cell::sync::OnceCell;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct Attempt {
    retries: u32,
    first_attempt_time: Instant,
    banned_until: Option<Instant>,
}

#[derive(Debug)]
pub struct RateLimiter {
    attempts: HashMap<IpAddr, Attempt>,
    max_retries: u32,
    find_time: Duration,
    ban_time: Duration,
}

/* RateLimiter Singleton Instance and Implementation */
static RATE_LIMITER_INSTANCE: OnceCell<Mutex<RateLimiter>> = OnceCell::new();
impl RateLimiter {
    pub fn global() -> Option<MutexGuard<'static, RateLimiter>> {
        RATE_LIMITER_INSTANCE
            .get()
            .map(|mutex| mutex.lock().unwrap())
    }

    pub fn initialize(max_retries: u32, find_time: Duration, ban_time: Duration) {
        // Create rate limiter instance with initialized values
        let rate_limiter = RateLimiter {
            attempts: HashMap::new(),
            max_retries,
            find_time,
            ban_time,
        };
        RATE_LIMITER_INSTANCE
            .set(Mutex::new(rate_limiter))
            .expect("Failed to initialize rate limiter");
    }

    pub fn is_banned(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        //initialize attempt
        let attempt = self.attempts.entry(ip).or_insert(Attempt {
            retries: 0,
            first_attempt_time: now,
            banned_until: None,
        });

        if let Some(banned_until) = attempt.banned_until {
            if now < banned_until {
                return true;
            } else {
                // Unban if the ban time has elapsed
                attempt.banned_until = None;
                attempt.retries = 0;
                attempt.first_attempt_time = now;
            }
        }

        false
    }

    pub fn record_failed_attempt(&mut self, ip: IpAddr) {
        let now = Instant::now();
        // initialize attempt (though should be there due to is_banned)
        let attempt = self.attempts.entry(ip).or_insert(Attempt {
            retries: 0,
            first_attempt_time: now,
            banned_until: None,
        });

        if now.duration_since(attempt.first_attempt_time) > self.find_time {
            // Reset the counter and time if outside the find_time window
            attempt.retries = 0;
            attempt.first_attempt_time = now;
        }

        attempt.retries += 1;

        if attempt.retries > self.max_retries {
            attempt.banned_until = Some(now + self.ban_time);
        }
    }
}
