# Kubernetes TLS Certificate Controller

This project implements a Kubernetes controller for TLS certificate management, 
allowing developers to request and manage TLS certificates through Kubernetes CR.

## Demo

![cert-manager](./demo.gif)

This demo showcases the controller in action, demonstrating the creation and management of TLS certificates.

## Project Structure

- [Dockerfile](./Dockerfile): Contains the instructions for building the controller's Docker image.
- [Controller Deployment](./config/manager/manager.yaml): Kubernetes deployment manifest for the controller.
- [RBAC Rules](./config/rbac): Cluster-scoped RBAC rules for the controller.
- [Custom Resource Definition (CRD)](./config/crd/bases/certs.k8c.io_certificates.yaml): Defines the Certificate custom resource.

All necessary manifests are combined in a single file for easy deployment: [install.yaml](./dist/install.yaml)

## How to Use

The certificate controller requires a functional Kubernetes cluster to operate.

### Running Locally

To run the operator locally for development or testing:

```bash
ENABLE_WEBHOOKS=false make run
```

Ensure that your `kubeconfig` is available in the `~/.kube` folder on your local machine.

### Deploying to a Kubernetes Cluster

The operator is available as a Docker image: `buraksekili/k8c-certmanager:latest`

To deploy the operator and all required resources (RBAC, CRDs, and Deployment) to your Kubernetes cluster:
```bash
make k8s
```

To remove the deployed resources:

```bash
make delete
```

## Using the Certificate Controller

Once the controller is running, you can create Certificate custom resources to request TLS certificates. 

Here's an example:

```bash
kubectl apply -f - <<EOF
    apiVersion: certs.k8c.io/v1
    kind: Certificate
    metadata:
      name: sample-app-cert
    spec:
      dnsName: sample-app.example.com
      validity: 2160h
      secretRef:
        name: sample-app-tls
EOF
```

> Example manifest is available in [./config/samples/cert.yaml](./config/samples/cert.yaml) file.

This will create a self-signed TLS certificate for `sample-app.example.com` valid for 90 days, 
stored in a Secret named `sample-app-tls`.

The status of custom resource can be used to track the reconciliation status.
```bash
kubectl describe certificates.certs.k8c.io sample-app-cert
# or
kubectl get certificates.certs.k8c.io sample-app-cert -o yaml
```

Operator logs are also available.

```bash
kubectl logs -n kubermatic-certmanager-system deployments/kubermatic-certmanager-controller-manager -f
```

### Shortname for CRD
Shortname for `certificates.certs.k8c.io` is defined as `c` if you do not want to type full name.
