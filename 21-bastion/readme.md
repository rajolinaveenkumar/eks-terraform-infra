# Run below command after bastion host created 

1. run "aws configure"
```
aws configure
```

2. The below command updates the kubeconfig file to allow interaction with AWS EKS cluster using kubectl
```
aws eks update-kubeconfig --region us-east-1 --name <my-cluster-name>
```
3. 
```
REGION_CODE=us-east-1
CLUSTER_NAME=expense-dev-eks
ACC_ID=343430925817
```

3. 
### Permissions
* OIDC provider
```
eksctl utils associate-iam-oidc-provider \
    --region $REGION_CODE \
    --cluster $CLUSTER_NAME \
    --approve
```
4.  IAM Policy
```
curl -o iam-policy.json https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.12.0/docs/install/iam_policy.json
```
5. Create IAM Policy
```
aws iam create-policy \
    --policy-name AWSLoadBalancerControllerIAMPolicy \
    --policy-document file://iam-policy.json
```
6. Provide access to EKS through IAM Policy
```
eksctl create iamserviceaccount \
--cluster=$CLUSTER_NAME \
--namespace=kube-system \
--name=aws-load-balancer-controller \
--attach-policy-arn=arn:aws:iam::$ACC_ID:policy/AWSLoadBalancerControllerIAMPolicy \
--override-existing-serviceaccounts \
--region $REGION_CODE \
--approve
```


### Helm already installed through bastion.sh

7. Add the EKS chart repo to Helm
```
helm repo add eks https://aws.github.io/eks-charts
```

* Install AWS Load Balancer Controller
```
helm install aws-load-balancer-controller eks/aws-load-balancer-controller -n kube-system --set clusterName=$CLUSTER_NAME --set serviceAccount.create=false --set serviceAccount.name=aws-load-balancer-controller
```

####
serviceAccount.create=false 

above sometimes fasle works some times true wokk, install accordingly