# argo-supply-chain-security
This project will focus on integrating software supply chain security into argo workflows

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
#### Setup the environment
will use k3d this requires docker 
``` sh
make setup-env
```

#### Build & deploy the controller locally
``` sh
make build-and-deploy-controller
```

#### Create a sample workflow to reconcile by the controller
``` sh
# run the workflow so controller can reconcile it update status & list the pod names of the workflow
kubectl create -f test/workflow/build-and-push-docker.yaml
```

#### Verify a secured artifact
``` sh
cosign verify --key k8s://argo-slsa/signing-secret [image]
```

### Aditional commands
#### remove the controller
``` sh
make remove-controller
```

#### stop the environment
``` sh
make stop-env
```

#### start the environment
``` sh
make start-env
```

#### Clean up environment
``` sh
make teardown-env
```
