# argo-supply-chain-security
This project will focus on integrating software supply chain security into argo workflows

### Create kubernetes cluster
will use k3d this requires docker
``` sh
k3d cluster create test
```
#### Stop or Start the cluster
``` sh
# Stop the cluster
k3d cluster stop test

# Start the cluster
k3d cluster start test
```

### install argo workflows in your cluster
``` sh
helm repo add argo https://argoproj.github.io/argo-helm
helm repo update
helm install argo argo/argo-workflows -n argo --create-namespace
```

# Controller creation process
Source : https://kubernetes.io/blog/2021/06/21/writing-a-controller-for-pod-labels/

### Initialiize operator
initializes the project
``` sh
operator-sdk init --domain=argo.slsa.io --repo=github.com/MohomedThariq/argo-supply-chain-security
```

### Create the controller template
create controller to watch argo Workflow crds
``` sh
operator-sdk create api --group=argoproj.io --version=v1alpha1 --kind=Workflow --controller=true --resource=false
```

### test the controller by running it
``` sh
make run
```