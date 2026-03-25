# Deploying a Zeek system-container in Kubernetes

## Requirements

Access to a multi-node Kubernetes clusters. For example, Digital Ocean's
Kubernetes [DOKS](https://www.digitalocean.com/products/kubernetes) or a
local [k3s](https://k3s.io/) installation on a few VMs.

## Walkthrough

Check that you have a few nodes available in the cluster:

    $ kubectl get nodes
    NAME                        STATUS   ROLES    AGE   VERSION
    zeek-pool-l703ekdjh-d8huf   Ready    <none>   30m   v1.35.1
    zeek-pool-l703ekdjh-d8huq   Ready    <none>   30m   v1.35.1
    zeek-pool-l703ekdjh-d8huy   Ready    <none>   31m   v1.35.1

Set the default namespace for kubectl to ``zeek`` for simplicity:

    $ kubectl config set-context --current --namespace=zeek

Deploy the "zeek" namespace and the zeek-standalone DaemonSet, check
``zeek-standalone.yaml`` for details.

    $ kubectl apply -f zeek-standalone.yaml

Now label one of the nodes with ``node.zeek.org/profile=standalone``. This
will make Kubernetes schedule a zeek-standalone pod on the node.

    $ kubectl label node zeek-pool-l703ekdjh-d8huf node.zeek.org/profile=standalone
    node/zeek-pool-l703ekdjh-d8huf labeled

After a few seconds, you should see something like this:

    $ kubectl get pods -o wide
    NAME                    READY   STATUS    RESTARTS   AGE     IP           NODE                        NOMINATED NODE   READINESS GATES
    zeek-standalone-cqhvx   1/1     Running   0          6m49s   10.114.0.4   zeek-pool-l703ekdjh-d8huq   <none>           <none>

    $ $ k exec zeek-standalone-cqhvx -- systemctl status
    ● zeek-pool-l703ekdjh-d8huq
        State: running
        Units: 112 loaded (incl. loaded aliases)
         Jobs: 0 queued
       Failed: 0 units
        Since: Fri 2026-03-20 14:39:37 UTC; 7min ago
      systemd: 257.9-1~deb13u1
      Tainted: unmerged-bin
       CGroup: /kubepods/besteffort/podbd36764c-fbdc-49c6-8eee-49ad3495b3f7/f47998fa4b4cb9b400ce19c2193bfe9798262d44769f91e27e9b9133cf3fd5ca
               ├─init.scope
               │ ├─  1 /sbin/init
               │ └─222 systemctl status
               ├─system.slice
               │ └─systemd-journald.service
               │   └─24 /usr/lib/systemd/systemd-journald
               └─zeek.slice
                 ├─zeek-archiver.slice
                 │ └─zeek-archiver.service
                 │   └─81 /usr/local/zeek/bin/zeek-archiver /usr/local/zeek/var/spool/zeek/log-queue /usr/local/zeek/var/logs/zeek
                 ├─zeek-loggers.slice
                 │ └─zeek-logger@1.service
                 │   └─82 /usr/local/zeek/bin/zeek policy/misc/systemd-generator local frameworks/cluster/backend/zeromq
                 ├─zeek-manager.slice
                 │ └─zeek-manager.service
                 │   └─83 /usr/local/zeek/bin/zeek policy/misc/systemd-generator local frameworks/cluster/backend/zeromq
                 ├─zeek-proxies.slice
                 │ ├─zeek-proxy@1.service
                 │ │ └─85 /usr/local/zeek/bin/zeek policy/misc/systemd-generator local frameworks/cluster/backend/zeromq
                 │ └─zeek-proxy@2.service
                 │   └─84 /usr/local/zeek/bin/zeek policy/misc/systemd-generator local frameworks/cluster/backend/zeromq
                 └─zeek-workers.slice
                   ├─zeek-worker@1.service
                   │ └─89 /usr/local/zeek/bin/zeek -i af_packet::eth0 policy/misc/systemd-generator local frameworks/cluster/backend/zeromq
                   ├─zeek-worker@2.service
                   │ └─86 /usr/local/zeek/bin/zeek -i af_packet::eth0 policy/misc/systemd-generator local frameworks/cluster/backend/zeromq
                   ├─zeek-worker@3.service
                   │ └─87 /usr/local/zeek/bin/zeek -i af_packet::eth0 policy/misc/systemd-generator local frameworks/cluster/backend/zeromq
                   └─zeek-worker@4.service
                     └─88 /usr/local/zeek/bin/zeek -i af_packet::eth0 policy/misc/systemd-generator local frameworks/cluster/backend/zeromq

## Summary

We just deployed a zeek-standalone pod with a single container running a Zeek
cluster on a single Kubernetes node by labeling it with ``node.zeek.org/profile=standalone``.

Not sure how to do multi-node clusters, yet.
