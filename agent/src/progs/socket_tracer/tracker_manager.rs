use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use socket_tracer_common::ConnId;

use crate::progs::socket_tracer::tracker::{ConnTracker, DEATH_COUNTDOWN_ITERS};

pub(crate) struct ConnTrackerGenerations {
    generations: HashMap<u64, Arc<ConnTracker>>,
    oldest_generation: Option<u64>,
}

impl ConnTrackerGenerations {
    pub(crate) fn new() -> Self {
        ConnTrackerGenerations {
            generations: HashMap::new(),
            oldest_generation: None,
        }
    }

    pub(crate) fn get_or_create(&mut self, conn_id: ConnId) -> Arc<ConnTracker> {
        let mut created = false;
        let conn_tracker = self
            .generations
            .entry(conn_id.tsid)
            .or_insert_with(|| {
                created = true;
                Arc::new(ConnTracker::new())
            })
            .clone();

        if created {
            if let Some(oldest_tsid) = self.oldest_generation {
                if conn_id.tsid < oldest_tsid {
                    conn_tracker.mark_for_death(DEATH_COUNTDOWN_ITERS);
                } else {
                    if let Some(oldest_tracker) = self.generations.get(&oldest_tsid) {
                        oldest_tracker.mark_for_death(DEATH_COUNTDOWN_ITERS);
                    }
                    self.oldest_generation = Some(conn_id.tsid);
                }
            } else {
                self.oldest_generation = Some(conn_id.tsid);
            }
        }

        conn_tracker
    }

    pub(crate) fn contains(&self, tsid: u64) -> bool {
        self.generations.contains_key(&tsid)
    }

    pub(crate) fn get_active(&self) -> Option<Arc<ConnTracker>> {
        if let Some(oldest_tsid) = self.oldest_generation {
            if let Some(oldest_tracker) = self.generations.get(&oldest_tsid) {
                if !oldest_tracker.ready_for_destruction() {
                    return Some(oldest_tracker.clone());
                }
            }
        }
        None
    }

    pub(crate) fn cleanup_generations(&mut self) -> usize {
        let mut num_erased = 0;
        self.generations.retain(|&tsid, tracker| {
            if tracker.ready_for_destruction() {
                if Some(tsid) == self.oldest_generation {
                    self.oldest_generation = None;
                }
                num_erased += 1;
                false
            } else {
                true
            }
        });
        num_erased
    }
}

pub(crate) struct ConnTrackerManager {
    conn_id_tracker_generations: RwLock<HashMap<u64, ConnTrackerGenerations>>,
}

impl ConnTrackerManager {
    pub(crate) fn new() -> Self {
        ConnTrackerManager {
            conn_id_tracker_generations: RwLock::new(HashMap::new()),
        }
    }

    pub(crate) fn get_or_create_conn_tracker(&self, conn_id: ConnId) -> Arc<ConnTracker> {
        let conn_map_key = conn_id.uid.tgid;
        let mut conn_id_tracker_generations = self.conn_id_tracker_generations.write();
        let conn_trackers = conn_id_tracker_generations
            .entry(conn_map_key)
            .or_insert_with(ConnTrackerGenerations::new);

        let conn_tracker = conn_trackers.get_or_create(conn_id);

        conn_tracker
    }

    pub(crate) fn get_conn_tracker(&self, conn_id: ConnId) -> Option<Arc<ConnTracker>> {
        let conn_id_tracker_generations = self.conn_id_tracker_generations.read();
        conn_id_tracker_generations
            .get(&conn_id.uid.tgid)
            .and_then(|tracker_generations| tracker_generations.get_active())
    }

    pub(crate) fn cleanup_trackers(&self) {
        let mut conn_id_tracker_generations = self.conn_id_tracker_generations.write();
        for tracker_generations in conn_id_tracker_generations.values_mut() {
            tracker_generations.cleanup_generations();
        }
    }
}
