# argo-supply-chain-security
This project will focus on integrating software supply chain security into argo workflows

### Setup the environment
will use k3d this requires docker 
``` sh
k3d cluster create test -v "${PWD}:/workspace@agent:*" -v "${PWD}:/workspace@server:*"
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
#### Create a namespace
``` sh
# this will be used to run the argo workflows
kubectl create namespace argo-slsa

# set the namespace as default
kubectl config set-context --current --namespace=argo-slsa

# set rbac for the namespaced sa
kubectl apply -f test/workflow/rbac/workflows-rbac.yaml
```
#### Create docker hub credentials
``` sh
kubectl create secret docker-registry docker-hub-credentials --docker-server=https://index.docker.io/v1/ --docker-username=<username> --docker-password=<password> --docker-email=<email>
```
#### Create keys for signing
``` sh
# create a key pair
cosign generate-key-pair k8s://<NAMESPACE>/<KEY>
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

# run the workflow so controller can reconcile it update status & list the pod names of the workflow
kubectl create -f test/workflow/build-and-push-docker.yaml
```