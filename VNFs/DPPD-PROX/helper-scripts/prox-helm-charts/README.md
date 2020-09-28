# PROX Packet pROcessing eXecution engine

PROX is a DPDK based application implementing Telco usecases and extensive NFVi testing engine.

# Introduction
This is the initial version of the Helm chart for the PROX deployment.

# Installation
1) Modify values.yaml file to match the desired test environment and reflect Kubernetes cluster set up.

2) Run
   From helper-scripts directory:

```console
$ helm package prox-helm-charts
$ helm install prox prox-0.1.0.tgz
```

3) Once the pod is started connect to it and run prox in the container

```console
$ cd /opt/rapid
$ ./prox -f /data/templates/swap.cfg
$ (or) ./prox -f /data/templates/gen.cfg
```

# Killing the deployment

To uninstall the chart

```console
$ helm uninstall prox
```
