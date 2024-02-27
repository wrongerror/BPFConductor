use std::sync::{Arc, RwLock};

use ahash::AHashMap;
use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::batch::v1::{CronJob, Job};
use k8s_openapi::api::core::v1::{Node, Pod, Service};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::runtime::reflector::store::Writer;
use kube::runtime::reflector::{ObjectRef, Store};
use kube::{
    api::Api,
    runtime::{predicates, reflector, watcher, WatchStreamExt},
    Client, ResourceExt,
};
use log::info;

type Cache<K, V> = Arc<RwLock<AHashMap<K, Arc<V>>>>;

#[derive(Clone, Debug, PartialEq)]
pub struct Workload {
    pub name: String,
    pub namespace: String,
    pub kind: String,
}

#[derive(Clone, Debug)]
pub struct ClusterStore {
    pub pods: Store<Pod>,
    pub nodes: Store<Node>,
    pub services: Store<Service>,
    pub replicasets: Store<ReplicaSet>,
    pub deployments: Store<Deployment>,
    pub statefulsets: Store<StatefulSet>,
    pub daemonsets: Store<DaemonSet>,
    pub jobs: Store<Job>,
    pub cronjobs: Store<CronJob>,
    pub pod_descriptors: Cache<ObjectRef<Pod>, Workload>,
}

#[derive(Clone, Debug)]
pub struct Resolver {
    store: ClusterStore,
    ips: Cache<String, Workload>,
}

macro_rules! spawn_watcher {
    ($resolver:expr, $resource:ty, $writer:expr, $watcher:ident) => {{
        let r = $resolver.clone();
        let writer = $writer;
        tokio::spawn(async move {
            let _ = r.$watcher(writer).await;
        })
    }};
}

impl Resolver {
    pub async fn new() -> anyhow::Result<Resolver> {
        info!("Initializing IPResolver");
        let (pod_reader, pod_writer) = reflector::store::<Pod>();
        let (node_reader, node_writer) = reflector::store::<Node>();
        let (svc_reader, svc_writer) = reflector::store::<Service>();
        let (rs_reader, rs_writer) = reflector::store::<ReplicaSet>();
        let (deploy_reader, deploy_writer) = reflector::store::<Deployment>();
        let (sts_reader, sts_writer) = reflector::store::<StatefulSet>();
        let (ds_reader, ds_writer) = reflector::store::<DaemonSet>();
        let (jobs_reader, jobs_writer) = reflector::store::<Job>();
        let (cronjobs_reader, cronjobs_writer) = reflector::store::<CronJob>();

        let cluster_store = ClusterStore {
            pods: pod_reader,
            nodes: node_reader,
            services: svc_reader,
            replicasets: rs_reader,
            deployments: deploy_reader,
            statefulsets: sts_reader,
            daemonsets: ds_reader,
            jobs: jobs_reader,
            cronjobs: cronjobs_reader,
            pod_descriptors: Arc::new(RwLock::new(AHashMap::new())),
        };

        let resolver = Resolver {
            store: cluster_store,
            ips: Arc::new(RwLock::new(AHashMap::new())),
        };

        spawn_watcher!(resolver, Pod, pod_writer, watching_pods);
        spawn_watcher!(resolver, Node, node_writer, watching_nodes);
        spawn_watcher!(resolver, Service, svc_writer, watching_services);
        spawn_watcher!(resolver, ReplicaSet, rs_writer, watching_replicasets);
        spawn_watcher!(resolver, Deployment, deploy_writer, watching_deployments);
        spawn_watcher!(resolver, StatefulSet, sts_writer, watching_statefulsets);
        spawn_watcher!(resolver, DaemonSet, ds_writer, watching_daemonsets);
        spawn_watcher!(resolver, Job, jobs_writer, watching_jobs);
        spawn_watcher!(resolver, CronJob, cronjobs_writer, watching_cronjobs);

        Ok(resolver)
    }

    pub fn resolve_ip(&self, ip: &str) -> Option<Arc<Workload>> {
        let ips = self.ips.read().unwrap();
        ips.get(ip).map(|w| w.clone())
    }

    async fn get_controller_of_owner(
        &self,
        owner_ref: OwnerReference,
        namespace: &str,
    ) -> Option<OwnerReference> {
        match owner_ref.kind.as_str() {
            "ReplicaSet" => {
                let reader = self.store.replicasets.clone();
                let obj_ref =
                    ObjectRef::<ReplicaSet>::new(owner_ref.name.as_str()).within(namespace);
                match reader.get(&obj_ref) {
                    Some(rs) => rs
                        .metadata
                        .owner_references
                        .as_ref()
                        .and_then(|refs| refs.iter().find(|r| r.controller == Some(true)))
                        .cloned(),
                    None => None,
                }
            }
            "Deployment" => {
                let reader = self.store.deployments.clone();
                let obj_ref =
                    ObjectRef::<Deployment>::new(owner_ref.name.as_str()).within(namespace);
                match reader.get(&obj_ref) {
                    None => None,
                    Some(deployment) => deployment
                        .metadata
                        .owner_references
                        .as_ref()
                        .and_then(|refs| refs.iter().find(|r| r.controller == Some(true)))
                        .cloned(),
                }
            }
            "DaemonSet" => {
                let reader = self.store.daemonsets.clone();
                let obj_ref =
                    ObjectRef::<DaemonSet>::new(owner_ref.name.as_str()).within(namespace);
                match reader.get(&obj_ref) {
                    None => None,
                    Some(daemonset) => daemonset
                        .metadata
                        .owner_references
                        .as_ref()
                        .and_then(|refs| refs.iter().find(|r| r.controller == Some(true)))
                        .cloned(),
                }
            }
            "StatefulSet" => {
                let reader = self.store.statefulsets.clone();
                let obj_ref =
                    ObjectRef::<StatefulSet>::new(owner_ref.name.as_str()).within(namespace);
                match reader.get(&obj_ref) {
                    None => None,
                    Some(statefulset) => statefulset
                        .metadata
                        .owner_references
                        .as_ref()
                        .and_then(|refs| refs.iter().find(|r| r.controller == Some(true)))
                        .cloned(),
                }
            }
            "Job" => {
                let reader = self.store.jobs.clone();
                let obj_ref = ObjectRef::<Job>::new(owner_ref.name.as_str()).within(namespace);
                match reader.get(&obj_ref) {
                    None => None,
                    Some(job) => job
                        .metadata
                        .owner_references
                        .as_ref()
                        .and_then(|refs| refs.iter().find(|r| r.controller == Some(true)))
                        .cloned(),
                }
            }
            "CronJob" => {
                let reader = self.store.cronjobs.clone();
                let obj_ref = ObjectRef::<CronJob>::new(owner_ref.name.as_str()).within(namespace);
                match reader.get(&obj_ref) {
                    None => None,
                    Some(cronjob) => cronjob
                        .metadata
                        .owner_references
                        .as_ref()
                        .and_then(|refs| refs.iter().find(|r| r.controller == Some(true)))
                        .cloned(),
                }
            }
            _ => None,
        }
    }

    async fn resolve_pod_descriptor(&self, pod: &Pod) -> Arc<Workload> {
        // if pod already exists in the cache, return it
        let entry = {
            let pod_descriptors = self.store.pod_descriptors.read().unwrap();
            if let Some(entry) = pod_descriptors.get(&ObjectRef::from_obj(pod)) {
                Some(entry.clone())
            } else {
                None
            }
        };

        if let Some(entry) = entry {
            return entry;
        }

        let mut name = pod.name_any();
        let namespace = pod.namespace().unwrap_or_default();
        let mut kind = "Pod".to_string();

        let mut owner_ref = pod
            .metadata
            .owner_references
            .as_ref()
            .and_then(|refs| refs.iter().find(|r| r.controller == Some(true)))
            .cloned();

        while let Some(owner) = owner_ref {
            let controller = self.get_controller_of_owner(owner, &*namespace).await;
            if let Some(ref controller) = controller {
                name = controller.name.clone();
                kind = controller.kind.clone();
            }
            owner_ref = controller;
        }

        let entry = Arc::new(Workload {
            name,
            namespace,
            kind,
        });
        let mut pod_descriptors = self.store.pod_descriptors.write().unwrap();
        pod_descriptors.insert(ObjectRef::from_obj(pod), entry.clone());
        entry
    }

    async fn watching_pods(&self, writer: Writer<Pod>) -> anyhow::Result<()> {
        let client = Client::try_default().await?;
        let api: Api<Pod> = Api::all(client);

        let stream = watcher(api, watcher::Config::default().any_semantic())
            .default_backoff()
            .modify(|pod| {
                pod.spec = None;
                pod.managed_fields_mut().clear();
                pod.annotations_mut().clear();
            })
            .reflect(writer)
            .applied_objects()
            .predicate_filter(predicates::resource_version);
        futures::pin_mut!(stream);

        while let Some(pod) = stream.try_next().await? {
            let entry = self.resolve_pod_descriptor(&pod).await;
            let mut ips = self.ips.write().unwrap();
            if let Some(status) = pod.status.as_ref() {
                if let Some(pod_ips) = status.pod_ips.as_ref() {
                    for ip in pod_ips {
                        ips.insert(ip.ip.clone().unwrap(), entry.clone());
                    }
                }
            }
        }

        Ok(())
    }

    async fn watching_nodes(&self, writer: Writer<Node>) -> anyhow::Result<()> {
        let client = Client::try_default().await?;
        let api: Api<Node> = Api::all(client);

        let stream = watcher(api, watcher::Config::default().any_semantic())
            .default_backoff()
            .modify(|node| {
                node.spec = None;
                node.metadata.managed_fields = None;
                node.metadata.annotations = None;
            })
            .reflect(writer)
            .applied_objects()
            .predicate_filter(predicates::resource_version);
        futures::pin_mut!(stream);

        while let Some(node) = stream.try_next().await? {
            let mut ips = self.ips.write().unwrap();
            if let Some(status) = node.status.as_ref() {
                if let Some(addresses) = status.addresses.as_ref() {
                    for addr in addresses {
                        ips.insert(
                            addr.address.clone(),
                            Arc::new(Workload {
                                name: node.name_any(),
                                namespace: "".to_string(),
                                kind: "Node".to_string(),
                            }),
                        );
                    }
                }
            }
        }

        Ok(())
    }

    async fn watching_services(&self, writer: Writer<Service>) -> anyhow::Result<()> {
        let client = Client::try_default().await?;
        let api: Api<Service> = Api::all(client);

        let stream = watcher(api, watcher::Config::default().any_semantic())
            .default_backoff()
            .modify(|service| {
                service.metadata.managed_fields = None;
                service.metadata.annotations = None;
            })
            .reflect(writer)
            .applied_objects()
            .predicate_filter(predicates::resource_version);
        futures::pin_mut!(stream);

        while let Some(service) = stream.try_next().await? {
            let mut ips = self.ips.write().unwrap();
            if let Some(spec) = service.spec.as_ref() {
                if let Some(cluster_ips) = spec.cluster_ips.as_ref() {
                    for ip in cluster_ips {
                        let ip = ip.clone().parse().unwrap();
                        // check if the ip is "None"
                        if ip == "None" {
                            continue;
                        }
                        ips.insert(
                            ip,
                            Arc::new(Workload {
                                name: service.name_any(),
                                namespace: service.namespace().unwrap_or_default(),
                                kind: "Service".to_string(),
                            }),
                        );
                    }
                }
            }
        }

        Ok(())
    }

    async fn watching_replicasets(&self, writer: Writer<ReplicaSet>) -> anyhow::Result<()> {
        let client = Client::try_default().await?;
        let api: Api<ReplicaSet> = Api::all(client);

        let stream = watcher(api, watcher::Config::default().any_semantic())
            .default_backoff()
            .modify(|replicaset| {
                replicaset.spec = None;
                replicaset.metadata.managed_fields = None;
                replicaset.metadata.annotations = None;
            })
            .reflect(writer)
            .applied_objects()
            .predicate_filter(predicates::resource_version);
        futures::pin_mut!(stream);

        stream.for_each(|_| futures::future::ready(())).await;

        Ok(())
    }

    async fn watching_deployments(&self, writer: Writer<Deployment>) -> anyhow::Result<()> {
        let client = Client::try_default().await?;
        let api: Api<Deployment> = Api::all(client);

        let stream = watcher(api, watcher::Config::default().any_semantic())
            .default_backoff()
            .modify(|deployment| {
                deployment.spec = None;
                deployment.metadata.managed_fields = None;
                deployment.metadata.annotations = None;
            })
            .reflect(writer)
            .applied_objects()
            .predicate_filter(predicates::resource_version);
        futures::pin_mut!(stream);
        stream.for_each(|_| futures::future::ready(())).await;
        Ok(())
    }

    async fn watching_daemonsets(&self, writer: Writer<DaemonSet>) -> anyhow::Result<()> {
        let client = Client::try_default().await?;
        let api: Api<DaemonSet> = Api::all(client);

        let stream = watcher(api, watcher::Config::default().any_semantic())
            .default_backoff()
            .modify(|daemonset| {
                daemonset.spec = None;
                daemonset.metadata.managed_fields = None;
                daemonset.metadata.annotations = None;
            })
            .reflect(writer)
            .applied_objects()
            .predicate_filter(predicates::resource_version);
        futures::pin_mut!(stream);
        stream.for_each(|_| futures::future::ready(())).await;

        Ok(())
    }

    async fn watching_statefulsets(&self, writer: Writer<StatefulSet>) -> anyhow::Result<()> {
        let client = Client::try_default().await?;
        let api: Api<StatefulSet> = Api::all(client);

        let stream = watcher(api, watcher::Config::default().any_semantic())
            .default_backoff()
            .modify(|statefulset| {
                statefulset.spec = None;
                statefulset.metadata.managed_fields = None;
                statefulset.metadata.annotations = None;
            })
            .reflect(writer)
            .applied_objects()
            .predicate_filter(predicates::resource_version);
        futures::pin_mut!(stream);
        stream.for_each(|_| futures::future::ready(())).await;
        Ok(())
    }

    async fn watching_jobs(&self, writer: Writer<Job>) -> anyhow::Result<()> {
        let client = Client::try_default().await?;
        let api: Api<Job> = Api::all(client);

        let stream = watcher(api, watcher::Config::default().any_semantic())
            .default_backoff()
            .modify(|job| {
                job.spec = None;
                job.metadata.managed_fields = None;
                job.metadata.annotations = None;
            })
            .reflect(writer)
            .applied_objects()
            .predicate_filter(predicates::resource_version);
        futures::pin_mut!(stream);
        stream.for_each(|_| futures::future::ready(())).await;
        Ok(())
    }

    async fn watching_cronjobs(&self, writer: Writer<CronJob>) -> anyhow::Result<()> {
        let client = Client::try_default().await?;
        let api: Api<CronJob> = Api::all(client);

        let stream = watcher(api, watcher::Config::default().any_semantic())
            .default_backoff()
            .modify(|cronjob| {
                cronjob.spec = None;
                cronjob.metadata.managed_fields = None;
                cronjob.metadata.annotations = None;
            })
            .reflect(writer)
            .applied_objects()
            .predicate_filter(predicates::resource_version);
        futures::pin_mut!(stream);
        stream.for_each(|_| futures::future::ready(())).await;
        Ok(())
    }

    pub async fn wait_for_cache_sync(&self) -> anyhow::Result<()> {
        let pods = self.store.pods.clone();
        pods.wait_until_ready().await?;
        let nodes = self.store.nodes.clone();
        nodes.wait_until_ready().await?;
        let services = self.store.services.clone();
        services.wait_until_ready().await?;
        let replicasets = self.store.replicasets.clone();
        replicasets.wait_until_ready().await?;
        let deployments = self.store.deployments.clone();
        deployments.wait_until_ready().await?;
        let statefulsets = self.store.statefulsets.clone();
        statefulsets.wait_until_ready().await?;
        let daemonsets = self.store.daemonsets.clone();
        daemonsets.wait_until_ready().await?;
        let jobs = self.store.jobs.clone();
        jobs.wait_until_ready().await?;
        let cronjobs = self.store.cronjobs.clone();
        cronjobs.wait_until_ready().await?;

        info!("Cache sync complete");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::ResourceExt;

    #[tokio::test]
    async fn test_new_resolver() {
        let r = Resolver::new().await.unwrap();
        r.wait_for_cache_sync().await.unwrap();
        let pods = r
            .store
            .pods
            .clone()
            .state()
            .iter()
            .map(|p| p.name_any())
            .collect::<Vec<_>>();
        assert_ne!(pods.len(), 0);

        let nodes = r
            .store
            .nodes
            .clone()
            .state()
            .iter()
            .map(|n| n.name_any())
            .collect::<Vec<_>>();
        assert_ne!(nodes.len(), 0);

        let services = r
            .store
            .services
            .clone()
            .state()
            .iter()
            .map(|s| s.name_any())
            .collect::<Vec<_>>();
        assert_ne!(services.len(), 0);

        let replicasets = r
            .store
            .replicasets
            .clone()
            .state()
            .iter()
            .map(|r| r.name_any())
            .collect::<Vec<_>>();
        assert_ne!(replicasets.len(), 0);

        let daemonsets = r
            .store
            .daemonsets
            .clone()
            .state()
            .iter()
            .map(|d| d.name_any())
            .collect::<Vec<_>>();
        assert_ne!(daemonsets.len(), 0);
    }

    #[tokio::test]
    async fn test_resolver_ip() {
        let r = Resolver::new().await.unwrap();
        r.wait_for_cache_sync().await.unwrap();
        let ip = "10.233.0.3";
        let except = Arc::new(Workload {
            name: "coredns".to_string(),
            namespace: "kube-system".to_string(),
            kind: "Service".to_string(),
        });
        let result = r.resolve_ip(ip);
        assert_eq!(result, Some(except));
    }
}
