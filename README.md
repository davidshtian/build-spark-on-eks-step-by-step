# Build Spark on EKS Step by Step
To help understand how Spark works and builds on AWS EKS.

> Notes: This repo mainly focused on the details to run Spark on EKS, and thus omitted some steps to create EKS cluster and related configurations, for these contents please refer to [Creating an Amazon EKS cluster](https://docs.aws.amazon.com/eks/latest/userguide/create-cluster.html).

## 0. Deploying Karpenter

> Notes: For auto-scaling part, this repo used Karpenter instead of Cluster Autoscaler.

For simplicity, here Fargete profile is leveraged for EKS compute resources, and the EKS cluster has already been created, and it might have some differences with the Karpenter docs on eksctl part, if you're under the same situation, please refer to [Migrating from Cluster Autoscaler
](https://karpenter.sh/v0.22.1/getting-started/migrating-from-cas/).

> Notes: As I used Fargete only cluster at first, refer to [Getting started with AWS Fargate using Amazon EKS
](https://docs.aws.amazon.com/eks/latest/userguide/fargate-getting-started.html) for patching coredns component. If not the case, just ignore this step.

```
kubectl patch deployment coredns \
    -n kube-system \
    --type json \
    -p='[{"op": "remove", "path": "/spec/template/metadata/annotations/eks.amazonaws.com~1compute-type"}]'
```

- Create IAM role for EC2 nodes provisioned by Karpenter
```
echo '{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}' > node-trust-policy.json

aws iam create-role --role-name KarpenterInstanceNodeRole \
    --assume-role-policy-document file://node-trust-policy.json
```
- Add policy for this role

```
aws iam attach-role-policy --role-name KarpenterInstanceNodeRole \
    --policy-arn arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy

aws iam attach-role-policy --role-name KarpenterInstanceNodeRole \
    --policy-arn arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy

aws iam attach-role-policy --role-name KarpenterInstanceNodeRole \
    --policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly

aws iam attach-role-policy --role-name KarpenterInstanceNodeRole \
    --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
```

- Create EC2 instance profile of the role
```
aws iam create-instance-profile \
    --instance-profile-name KarpenterInstanceProfile

aws iam add-role-to-instance-profile \
    --instance-profile-name KarpenterInstanceProfile \
    --role-name KarpenterInstanceNodeRole
```

- Get EKS cluster information
```
CLUSTER_NAME=<your cluster name>

CLUSTER_ENDPOINT="$(aws eks describe-cluster \
    --name ${CLUSTER_NAME} --query "cluster.endpoint" \
    --output text)" && echo $CLUSTER_ENDPOINT
OIDC_ENDPOINT="$(aws eks describe-cluster --name ${CLUSTER_NAME} \
    --query "cluster.identity.oidc.issuer" --output text)" && echo $OIDC_ENDPOINT
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' \
    --output text) && echo $AWS_ACCOUNT_ID

```

- Create IRSA role for Karpenter controller
```
echo "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [
        {
            \"Effect\": \"Allow\",
            \"Principal\": {
                \"Federated\": \"arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_ENDPOINT#*//}\"
            },
            \"Action\": \"sts:AssumeRoleWithWebIdentity\",
            \"Condition\": {
                \"StringEquals\": {
                    \"${OIDC_ENDPOINT#*//}:aud\": \"sts.amazonaws.com\",
                    \"${OIDC_ENDPOINT#*//}:sub\": \"system:serviceaccount:karpenter:karpenter\"
                }
            }
        }
    ]
}" > controller-trust-policy.json

aws iam create-role --role-name KarpenterControllerRole-${CLUSTER_NAME} \
    --assume-role-policy-document file://controller-trust-policy.json

echo '{
    "Statement": [
        {
            "Action": [
                "ssm:GetParameter",
                "iam:PassRole",
                "ec2:DescribeImages",
                "ec2:RunInstances",
                "ec2:DescribeSubnets",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeLaunchTemplates",
                "ec2:DescribeInstances",
                "ec2:DescribeInstanceTypes",
                "ec2:DescribeInstanceTypeOfferings",
                "ec2:DescribeAvailabilityZones",
                "ec2:DeleteLaunchTemplate",
                "ec2:CreateTags",
                "ec2:CreateLaunchTemplate",
                "ec2:CreateFleet",
                "ec2:DescribeSpotPriceHistory",
                "pricing:GetProducts"
            ],
            "Effect": "Allow",
            "Resource": "*",
            "Sid": "Karpenter"
        },
        {
            "Action": "ec2:TerminateInstances",
            "Condition": {
                "StringLike": {
                    "ec2:ResourceTag/Name": "*karpenter*"
                }
            },
            "Effect": "Allow",
            "Resource": "*",
            "Sid": "ConditionalEC2Termination"
        }
    ],
    "Version": "2012-10-17"
}' > controller-policy.json

aws iam put-role-policy --role-name KarpenterControllerRole-${CLUSTER_NAME} \
    --policy-name KarpenterControllerPolicy-${CLUSTER_NAME} \
    --policy-document file://controller-policy.json
```

- Add tags for subnets and security groups

> Notes: As nodegroup was not created before, here first to get the resource information.
```
SECURITY_GROUPS=$(aws eks describe-cluster \
    --name ${CLUSTER_NAME} --query "cluster.resourcesVpcConfig.clusterSecurityGroupId" --output text)

aws ec2 create-tags \
    --tags "Key=karpenter.sh/discovery,Value=${CLUSTER_NAME}" \
    --resources ${SECURITY_GROUPS}

for SUBNET in $(aws eks describe-cluster \
    --name ${CLUSTER_NAME} --query "cluster.resourcesVpcConfig.subnetIds" --output text);
    do aws ec2 create-tags \
    --tags "Key=karpenter.sh/discovery,Value=${CLUSTER_NAME}" --resources ${SUBNET}
done
```

- Add role mapping to aws-auth config map
```
    - groups:
      - system:bootstrappers
      - system:nodes
      rolearn: arn:aws:iam::<your aws account>:role/KarpenterInstanceNodeRole
      username: system:node:{{EC2PrivateDNSName}}
```

- Update helm template

> Notes: Only helm 3.8.0+ support oci.

```
helm template karpenter oci://public.ecr.aws/karpenter/karpenter --version ${KARPENTER_VERSION} --namespace karpenter \
    --set settings.aws.defaultInstanceProfile=KarpenterInstanceProfile \
    --set settings.aws.clusterEndpoint="${CLUSTER_ENDPOINT}" \
    --set settings.aws.clusterName=${CLUSTER_NAME} \
    --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"="arn:aws:iam::${AWS_ACCOUNT_ID}:role/KarpenterControllerRole-${CLUSTER_NAME}" \
    --version ${KARPENTER_VERSION} > karpenter.yaml
```

- Create Karpenter CRD and other resources
```
kubectl create namespace karpenter
kubectl create -f \
    https://raw.githubusercontent.com/aws/karpenter/${KARPENTER_VERSION}/pkg/apis/crds/karpenter.sh_provisioners.yaml
kubectl create -f \
    https://raw.githubusercontent.com/aws/karpenter/${KARPENTER_VERSION}/pkg/apis/crds/karpenter.k8s.aws_awsnodetemplates.yaml
kubectl apply -f karpenter.yaml
```

If you encountered "readiness probe failed" error as below:
```
Events:
  Type     Reason           Age               From               Message
  ----     ------           ----              ----               -------
  Warning  LoggingDisabled  102s              fargate-scheduler  Disabled logging because aws-logging configmap was not found. configmap "aws-logging" not found
  Normal   Scheduled        60s               fargate-scheduler  Successfully assigned karpenter/karpenter-6dc598795f-cm265 to fargate-ip-172-31-192-45.ec2.internal
  Normal   Pulling          60s               kubelet            Pulling image "public.ecr.aws/karpenter/controller:v0.22.0@sha256:33580038c91ba11a88083ccf8f2848bee3f916e70d8bfd25f83f79b2a7a739f7"
  Normal   Pulled           58s               kubelet            Successfully pulled image "public.ecr.aws/karpenter/controller:v0.22.0@sha256:33580038c91ba11a88083ccf8f2848bee3f916e70d8bfd25f83f79b2a7a739f7" in 1.768581794s
  Warning  Unhealthy        57s               kubelet            Readiness probe failed: Get "http://172.31.192.45:8081/readyz": dial tcp 172.31.192.45:8081: connect: connection refused
  Warning  Unhealthy        55s               kubelet            Readiness probe failed: Get "http://172.31.192.45:8081/readyz": read tcp 169.254.175.250:53138->172.31.192.45:8081: read: connection reset by peer
  Warning  Unhealthy        34s               kubelet            Readiness probe failed: Get "http://172.31.192.45:8081/readyz": read tcp 169.254.175.250:37926->172.31.192.45:8081: read: connection reset by peer
  Normal   Started          3s (x4 over 58s)  kubelet            Started container controller
  Normal   Pulled           3s (x3 over 56s)  kubelet            Container image "public.ecr.aws/karpenter/controller:v0.22.0@sha256:33580038c91ba11a88083ccf8f2848bee3f916e70d8bfd25f83f79b2a7a739f7" already present on machine
  Normal   Created          3s (x4 over 58s)  kubelet            Created container controller
  Warning  Unhealthy        2s                kubelet            Readiness probe failed: Get "http://172.31.192.45:8081/readyz": read tcp 169.254.175.250:38162->172.31.192.45:8081: read: connection reset by peer
  Warning  BackOff          1s (x8 over 54s)  kubelet            Back-off restarting failed container
```

Keep diving the pod logs:
```
2023-01-07T10:20:09.047Z    FATAL   controller.aws  Checking EC2 API connectivity, WebIdentityErr: failed to retrieve credentials
caused by: InvalidIdentityToken: No OpenIDConnect provider found in your account for https://oidc.eks.us-east-1.amazonaws.com/id/C8D84A9C57A305C656523B188F45xxxx
    status code: 400, request id: 59709642-4335-45ba-8209-d420b92bde1e  {"commit": "038d219-dirty"}
```

Forgot to create OIDC provider... Refer to [Creating an IAM OIDC provider for your cluster
](https://docs.aws.amazon.com/eks/latest/userguide/enable-iam-roles-for-service-accounts.html) for configration, after that karpenter controller pod was created successfulluy.

- Create provisioner
```
echo 'apiVersion: karpenter.sh/v1alpha5
kind: Provisioner
metadata:
  name: spark-memory-optimized
  namespace: karpenter
spec:
  kubeletConfiguration:
    containerRuntime: containerd
#    podsPerCore: 2
#    maxPods: 20
  requirements:
    - key: "topology.kubernetes.io/zone"
      operator: In
      values: ["us-east-1c"] #Update the correct region and zone
    - key: "karpenter.sh/capacity-type"
      operator: In
      values: ["on-demand"]
    - key: "node.kubernetes.io/instance-type" #If not included, all instance types are considered
      operator: In
      values: ["r5d.large","r5d.xlarge","r5d.2xlarge"] # 2 NVMe disk
    - key: "kubernetes.io/arch"
      operator: In
      values: ["amd64"]
  limits:
    resources:
      cpu: 20
  providerRef: # optional, recommended to use instead of `provider`
    name: spark-memory-optimized
  labels:
    type: karpenter
    provisioner: spark-memory-optimized
    NodeGroupType: SparkMemoryOptimized
  taints:
    - key: spark-memory-optimized
      value: "true"
      effect: NoSchedule
  ttlSecondsAfterEmpty: 120 # optional, but never scales down if not set
' > spark-memory-optimized-provisioner.yaml
```

- Create node template
```
echo 'apiVersion: karpenter.k8s.aws/v1alpha1
kind: AWSNodeTemplate
metadata:
  name: spark-memory-optimized
  namespace: karpenter
spec:
  blockDeviceMappings:
    - deviceName: /dev/xvda
      ebs:
        volumeSize: 200Gi
        volumeType: gp3
        encrypted: true
        deleteOnTermination: true
  subnetSelector:
    aws-ids: "subnet-6504ee2f"        # Name of the Subnets to spin up the nodes
  securityGroupSelector:                      # required, when not using launchTemplate
    Name: "default"           # name of the SecurityGroup to be used with Nodes
  userData: |
    MIME-Version: 1.0
    Content-Type: multipart/mixed; boundary="BOUNDARY"

    --BOUNDARY
    Content-Type: text/x-shellscript; charset="us-ascii"

    #!/bin/bash
    <your own bootstrap logic>

    --BOUNDARY--

  tags:
    InstanceType: "spark-memory-optimized"    # optional, add tags for your own use
' > spark-memory-optimized-template.yaml
```

- Create deployment to test karpenter
```
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: inflate
spec:
  replicas: 0
  selector:
    matchLabels:
      app: inflate
  template:
    metadata:
      labels:
        app: inflate
    spec:
      terminationGracePeriodSeconds: 0
      tolerations:
        - key: "spark-memory-optimized"
          operator: "Exists"
          effect: "NoSchedule"
      containers:
        - name: inflate
          image: public.ecr.aws/eks-distro/kubernetes/pause:3.7
          resources:
            requests:
              cpu: 1
EOF
```

- Verify karpenter
```
kubectl scale deployment inflate --replicas 5
kubectl logs -f -n karpenter -c controller -l app.kubernetes.io/name=karpenter
```

Examine the logs:
```
2023-01-07T11:14:16.803Z    INFO    controller.provisioner  launching node with 5 pods requesting {"cpu":"5125m","pods":"7"} from types r5d.2xlarge {"commit": "038d219-dirty", "provisioner": "spark-memory-optimized"}
2023-01-07T11:14:17.136Z    DEBUG   controller.provisioner.cloudprovider    discovered security groups  {"commit": "038d219-dirty", "provisioner": "spark-memory-optimized", "security-groups": ["sg-7a5bf40c"]}
2023-01-07T11:14:17.139Z    DEBUG   controller.provisioner.cloudprovider    discovered kubernetes version   {"commit": "038d219-dirty", "provisioner": "spark-memory-optimized", "kubernetes-version": "1.24"}
2023-01-07T11:14:17.175Z    DEBUG   controller.provisioner.cloudprovider    discovered new ami  {"commit": "038d219-dirty", "provisioner": "spark-memory-optimized", "ami": "ami-074963e096747169d", "query": "/aws/service/eks/optimized-ami/1.24/amazon-linux-2/recommended/image_id"}
2023-01-07T11:14:17.328Z    DEBUG   controller.provisioner.cloudprovider    created launch template {"commit": "038d219-dirty", "provisioner": "spark-memory-optimized", "launch-template-name": "Karpenter-spark-10036198655915325837", "launch-template-id": "lt-06acaf73509884d78"}
2023-01-07T11:14:19.335Z    INFO    controller.provisioner.cloudprovider    launched new instance   {"commit": "038d219-dirty", "provisioner": "spark-memory-optimized", "launched-instance": "i-01f2c1bdc4acd3646", "hostname": "ip-172-31-25-95.ec2.internal", "type": "r5d.2xlarge", "zone": "us-east-1c", "capacity-type": "on-demand"}
```

## 1. Build Container Image

> Notes: For my own build enviroment, docker host network mode was used specifically, please modify ./bin/docker-image-tool.sh script and add --network=host in related commands. If not the case, just ignore the host networking part.

- Download Spark package:
```
wget https://dlcdn.apache.org/spark/spark-3.3.1/spark-3.3.1-bin-hadoop3.tgz
tar zxvf spark-3.3.1-bin-hadoop3.tgz
cd spark-3.3.1-bin-hadoop3
```

- And also AWS jar files:
```
cd jars
wget https://repo1.maven.org/maven2/com/amazonaws/aws-java-sdk-bundle/1.11.901/aws-java-sdk-bundle-1.11.901.jar
wget https://repo1.maven.org/maven2/org/apache/hadoop/hadoop-aws/3.3.1/hadoop-aws-3.3.1.jar
```

- Install buildx (for both x86 and arm platforms)

Refer to [Install the docker buildx plugin with a builder to build arm containers](https://github.com/buildkite/elastic-ci-stack-for-aws/issues/765).
```
# install docker buildx globally
DOCKER_DIR=/usr/libexec/docker
## get latest version or pin it to v0.4.2
BUILDX_VERSION=$(curl --silent "https://api.github.com/repos/docker/buildx/releases/latest" | jq -r '.tag_name')
mkdir -p $DOCKER_DIR/cli-plugins

## check architecture
UNAME_ARCH=`uname -m`
case $UNAME_ARCH in
  aarch64)
    BUILDX_ARCH="arm64";
    ;;
  amd64)
    BUILDX_ARCH="amd64";
    ;;
  *)
    BUILDX_ARCH="amd64";
    ;;
esac

wget \
  -O $DOCKER_DIR/cli-plugins/docker-buildx \
  -nv https://github.com/docker/buildx/releases/download/$BUILDX_VERSION/buildx-$BUILDX_VERSION.linux-$BUILDX_ARCH
chmod a+x $DOCKER_DIR/cli-plugins/docker-buildx
```

Create a buildx builder, otherwise it may throw errors like *ERROR: multiple platforms feature is currently not supported for docker driver. Please switch to a different driver (eg. "docker buildx create --use")*, refer to [Docker buildx support multiple architectures images](https://cloudolife.com/2022/03/05/Infrastructure-as-Code-IaC/Container/Docker/Docker-buildx-support-multiple-architectures-images/).

> Notes: buildkitd-flags need to be added, otherwise it may throw errors like *ERROR: failed to solve: granting entitlement network.host is not allowed by build daemon configuration*.

```
docker buildx create --use --name mybuilder --driver-opt network=host --buildkitd-flags '--allow-insecure-entitlement network.host'
docker buildx inspect --bootstrap
```

> Notes: buildkitd-flags need to be added, otherwise it may throw errors like *#0 0.072 .buildkit_qemu_emulator: /bin/sh: Invalid ELF image for this architecture*

Configure multiarch/qemu-user-static:
```
docker run --rm --privileged multiarch/qemu-user-static --reset
```

Some other references used during troubleshooting: 

[Push multi-arch docker image](https://hackfi.initedit.com/2022/08/11/push-multi-arch-docker-image/)

[Building Windows multi-arch container images on Linux](https://lippertmarkus.com/2021/11/30/win-multiarch-img-lin/)

[Running Cross-Architecture Containers](https://docs.nvidia.com/datacenter/cloud-native/playground/x-arch.html)

[How to run arm64 containers from amd64 hosts (and vice versa)?](https://www.reddit.com/r/docker/comments/c75uhq/how_to_run_arm64_containers_from_amd64_hosts_and/)

[Building Multi-Architecture Docker Images With Buildx](https://medium.com/@artur.klauser/building-multi-architecture-docker-images-with-buildx-27d80f7e2408)

[Where did the built multi-platform image go?](https://github.com/docker/buildx/issues/166)

- Build the images
```
./bin/docker-image-tool.sh -r <your aws account>.dkr.ecr.us-east-1.amazonaws.com/sparkonk8s -t v3.3.1 -p kubernetes/dockerfiles/spark/bindings/python/Dockerfile -X build
```

> Notes: Please configure related ECR permissions, otherwise the push might be hang.

## 2. Configure S3 Access

- Create spark namespace
```
k create ns spark
```

- Create policy with s3 full access
```
cat >my-policy.json <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:*"
            ],
            "Resource": "*"
        }
    ]
}
EOF

aws iam create-policy --policy-name spark-eks --policy-document file://my-policy.json
```

- Create service account
```
cat >spark-service-account.yaml <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: spark-sa
  namespace: spark
EOF
kubectl apply -f spark-service-account.yaml
```

- Configure IRSA
```
account_id=$(aws sts get-caller-identity --query "Account" --output text)

oidc_provider=$(aws eks describe-cluster --name spark --region us-east-1 --query "cluster.identity.oidc.issuer" --output text | sed -e "s/^https:\/\///")

export namespace=spark
export service_account=spark-sa

cat >trust-relationship.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::$account_id:oidc-provider/$oidc_provider"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${oidc_provider}:aud": "sts.amazonaws.com",
          "${oidc_provider}:sub": "system:serviceaccount:$namespace:$service_account"
        }
      }
    }
  ]
}
EOF
aws iam create-role --role-name spark-eks --assume-role-policy-document file://trust-relationship.json --description "spark on eks role"

aws iam attach-role-policy --role-name spark-eks --policy-arn=arn:aws:iam::$account_id:policy/spark-eks

kubectl annotate serviceaccount -n $namespace $service_account eks.amazonaws.com/role-arn=arn:aws:iam::$account_id:role/spark-eks
```

- Create config map for tolerating karpenter taint
```
kind: ConfigMap
apiVersion: v1
metadata:
  name: spark-eks-pod-template
  namespace: spark
data:
  driver: |-
    apiVersion: v1
    kind: Pod
    spec:
      serviceAccountName: spark-sa
      tolerations:
        - key: "spark-memory-optimized"
          operator: "Exists"
          effect: "NoSchedule"

  executor: |-
    apiVersion: v1
    kind: Pod
    spec:
      serviceAccountName: spark-sa
      tolerations:
        - key: "spark-memory-optimized"
          operator: "Exists"
          effect: "NoSchedule"
```

- Create pod
```
apiVersion: v1
kind: Pod
metadata:
  name: spark-py
  namespace: spark
spec:
  serviceAccountName: spark-sa
  tolerations:
  - key: "spark-memory-optimized"
    operator: "Exists"
    effect: "NoSchedule"
  containers:
  - name: spark-py
    image: <your aws account>.dkr.ecr.us-east-1.amazonaws.com/sparkonk8s/spark-py:v3.3.1
    args: [ "/bin/bash", "-c", "--", "while true; do sleep 30; done;" ]
    volumeMounts:
    - name: spark-pod-template
      mountPath: /opt/spark/conf/driver_pod_template.yml
      subPath: driver
    - name: spark-pod-template
      mountPath: /opt/spark/conf/executor_pod_template.yml
      subPath: executor
  volumes:
  - name: spark-pod-template
    configMap:
     name: spark-eks-pod-template
     defaultMode: 420
```

- Create role and role binding
```
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: spark
  name: spark-role
rules:
- apiGroups: ["", "extensions", "apps"]
  resources: ["*"]
  verbs: ["*"]
---
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: spark-role-binding
  namespace: spark
subjects:
- kind: ServiceAccount
  name: spark-sa
  namespace: spark
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: spark-role
```

- Test pod s3 access
```
k -n spark exec -it spark-py -- bash

/opt/spark/bin/pyspark -c "fs.s3a.aws.credentials.provider"="com.amazonaws.auth.WebIdentityTokenCredentialsProvider"
```

- Submit local task
```
/opt/spark/bin/spark-submit \
    --master k8s://https://kubernetes.default.svc \
    --deploy-mode cluster \
    --name spark-py \
    --conf spark.kubernetes.namespace=spark \
    --conf spark.executor.instances=1 \
    --conf spark.kubernetes.container.image=<your aws account>.dkr.ecr.us-east-1.amazonaws.com/sparkonk8s/spark-py:v3.3.1 \
    --conf spark.kubernetes.driver.podTemplateFile='/opt/spark/conf/driver_pod_template.yml' \
    --conf spark.kubernetes.executor.podTemplateFile='/opt/spark/conf/executor_pod_template.yml' \
    local:///opt/spark/examples/src/main/python/wordcount.py /opt/spark/examples/src/main/resources/people.txt
```
Refer to [Best practices for running Spark on Amazon EKS](https://aws.amazon.com/cn/blogs/containers/best-practices-for-running-spark-on-amazon-eks/).

- Create spark-defaults configmap for s3 access (and glue for later usage)
```
apiVersion: v1
kind: ConfigMap
metadata:
  name: spark-defaults
  namespace: spark
data:
  spark-defaults.conf: |
    spark.hadoop.fs.s3a.path.style.access true
    spark.hadoop.fs.s3a.aws.credentials.provider com.amazonaws.auth.WebIdentityTokenCredentialsProvider
    spark.hadoop.fs.s3.impl org.apache.hadoop.fs.s3a.S3AFileSystem
    spark.hive.imetastoreclient.factory.class com.amazonaws.glue.catalog.metastore.AWSGlueDataCatalogHiveClientFactory
```

> Notes: Configure spark.hadoop.fs.s3a.path.style.access true, otherwise it may throw error like Caused by: javax.net.ssl.SSLPeerUnverifiedException: Certificate for <us-east-1.elasticmapreduce.s3.amazonaws.com> doesn't match any of the subject alternative names: [*.s3.amazonaws.com, s3.amazonaws.com]，

Refer to [Spark With AWS S3 running with docker - Certificate does not match any of the subject alternative names](https://stackoverflow.com/questions/72402976/spark-with-aws-s3-running-with-docker-certificate-does-not-match-any-of-the-su).

- Recreate pod
```
apiVersion: v1
kind: Pod
metadata:
  name: spark-py
  namespace: spark
spec:
  serviceAccountName: spark-sa
  tolerations:
  - key: "spark-memory-optimized"
    operator: "Exists"
    effect: "NoSchedule"
  containers:
  - name: spark-py
    image: <your aws account>.dkr.ecr.us-east-1.amazonaws.com/sparkonk8s/spark-py:v3.3.1
    args: [ "/bin/bash", "-c", "--", "while true; do sleep 30; done;" ]
    volumeMounts:
    - name: spark-pod-template
      mountPath: /opt/spark/conf/driver_pod_template.yml
      subPath: driver
    - name: spark-pod-template
      mountPath: /opt/spark/conf/executor_pod_template.yml
      subPath: executor
    - name: spark-defaults
      mountPath: /opt/spark/conf/spark-defaults.conf
      subPath: spark-defaults.conf
  volumes:
  - name: spark-pod-template
    configMap:
     name: spark-eks-pod-template
     defaultMode: 420
  - name: spark-defaults
    configMap:
     name: spark-defaults
     defaultMode: 420
```

## 3. Integrate with Glue Metastore

- Copmpile hive and spark client packages

Refer to [https://github.com/awslabs/aws-glue-data-catalog-client-for-apache-hive-metastore](https://github.com/awslabs/aws-glue-data-catalog-client-for-apache-hive-metastore). You could upload packages to S3 bucket.

- Replace with new compiled jar files
Back to spark folder:
```
cd jars
rm hive-*

aws s3 cp s3://<your s3 bucket>/jars/hive-beeline-2.3.10-SNAPSHOT.jar .
aws s3 cp s3://<your s3 bucket>/jars/hive-cli-2.3.10-SNAPSHOT.jar .
aws s3 cp s3://<your s3 bucket>/jars/hive-common-2.3.10-SNAPSHOT.jar .
aws s3 cp s3://<your s3 bucket>/jars/hive-exec-2.3.10-SNAPSHOT-core.jar .
aws s3 cp s3://<your s3 bucket>/jars/hive-jdbc-2.3.10-SNAPSHOT.jar .
aws s3 cp s3://<your s3 bucket>/jars/hive-llap-common-2.3.10-SNAPSHOT.jar .
aws s3 cp s3://<your s3 bucket>/jars/hive-metastore-2.3.10-SNAPSHOT.jar .
aws s3 cp s3://<your s3 bucket>/jars/hive-serde-2.3.10-SNAPSHOT.jar .
aws s3 cp s3://<your s3 bucket>/jars/hive-service-rpc-2.3.10-SNAPSHOT.jar .
aws s3 cp s3://<your s3 bucket>/jars/hive-shims-0.23-2.3.10-SNAPSHOT.jar .
aws s3 cp s3://<your s3 bucket>/jars/hive-shims-2.3.10-SNAPSHOT.jar .
aws s3 cp s3://<your s3 bucket>/jars/hive-shims-common-2.3.10-SNAPSHOT.jar .
aws s3 cp s3://<your s3 bucket>/jars/hive-shims-scheduler-2.3.10-SNAPSHOT.jar .
aws s3 cp s3://<your s3 bucket>/jars/hive-storage-api-2.7.2.jar .
aws s3 cp s3://<your s3 bucket>/jars/hive-vector-code-gen-2.3.10-SNAPSHOT.jar .
aws s3 cp s3://<your s3 bucket>/jars/spark-client-2.3.10-SNAPSHOT.jar .
aws s3 cp s3://<your s3 bucket>/jars/aws-glue-datacatalog-spark-client-3.4.0-SNAPSHOT.jar .
```

- Update config map
```
kind: ConfigMap
apiVersion: v1
metadata:
  name: spark-eks-pod-template
  namespace: spark
data:
  driver: |-
    apiVersion: v1
    kind: Pod
    spec:
      imagePullPolicy: Always
      volumeMounts:
      - name: spark-defaults
        mountPath: /opt/spark/conf/spark-defaults.conf
        subPath: spark-defaults.conf
      volumes:
      - name: spark-defaults
        configMap:
          name: spark-defaults
          defaultMode: 420
      serviceAccountName: spark-sa
      tolerations:
        - key: "spark-memory-optimized"
          operator: "Exists"
          effect: "NoSchedule"

  executor: |-
    apiVersion: v1
    kind: Pod
    spec:
      imagePullPolicy: Always
      volumeMounts:
      - name: spark-defaults
        mountPath: /opt/spark/conf/spark-defaults.conf
        subPath: spark-defaults.conf
      volumes:
      - name: spark-defaults
        configMap:
          name: spark-defaults
          defaultMode: 420
      serviceAccountName: spark-sa
      tolerations:
        - key: "spark-memory-optimized"
          operator: "Exists"
          effect: "NoSchedule"
```

- Submit task (local script, s3 data)
```
/opt/spark/bin/spark-submit \
    --master k8s://https://kubernetes.default.svc \
    --deploy-mode cluster \
    --name spark-s3 \
    --conf spark.kubernetes.namespace=spark \
    --conf spark.executor.instances=1 \
    --conf spark.kubernetes.container.image=<your aws account>.dkr.ecr.us-east-1.amazonaws.com/sparkonk8s/spark-py:v3.3.1 \
    --conf spark.kubernetes.driver.podTemplateFile='/opt/spark/conf/driver_pod_template.yml' \
    --conf spark.kubernetes.executor.podTemplateFile='/opt/spark/conf/executor_pod_template.yml' \
    local:///opt/spark/examples/src/main/python/wordcount.py s3://<your s3 bucket>/scripts/wordcount.py
```

- Submit task (s3 script, s3 data)
```
/opt/spark/bin/spark-submit \
    --master k8s://https://kubernetes.default.svc \
    --deploy-mode cluster \
    --name spark-s3 \
    --conf spark.kubernetes.namespace=spark \
    --conf spark.executor.instances=1 \
    --conf spark.kubernetes.container.image=<your aws account>.dkr.ecr.us-east-1.amazonaws.com/sparkonk8s/spark-py:v3.3.1 \
    --conf spark.kubernetes.driver.podTemplateFile='/opt/spark/conf/driver_pod_template.yml' \
    --conf spark.kubernetes.executor.podTemplateFile='/opt/spark/conf/executor_pod_template.yml' \
    s3://<your s3 bucket>/spark-on-eks/scripts/wc.py s3://<your s3 bucket>/spark-on-eks/scripts/wc.py
```

wc.py content:
```
import sys
from operator import add
from pyspark.sql import SparkSession
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: wordcount <file>", file=sys.stderr)
        sys.exit(-1)
    spark = SparkSession\
        .builder\
        .appName("PythonWordCount")\
        .getOrCreate()
    lines = spark.read.text(sys.argv[1]).rdd.map(lambda r: r[0])
    counts = lines.flatMap(lambda x: x.split(' ')) \
                  .map(lambda x: (x, 1)) \
                  .reduceByKey(add)
    output = counts.collect()
    for (word, count) in output:
        print("%s: %i" % (word, count))
    spark.stop()
```

- Submit task (s3 script, s3 data)
```
/opt/spark/bin/spark-submit \
    --master k8s://https://kubernetes.default.svc \
    --deploy-mode cluster \
    --name spark-s3 \
    --conf spark.kubernetes.namespace=spark \
    --conf spark.executor.instances=1 \
    --conf spark.kubernetes.container.image=<your aws account>.dkr.ecr.us-east-1.amazonaws.com/sparkonk8s/spark-py:v3.3.1 \
    --conf spark.kubernetes.driver.podTemplateFile='/opt/spark/conf/driver_pod_template.yml' \
    --conf spark.kubernetes.executor.podTemplateFile='/opt/spark/conf/executor_pod_template.yml' \
    s3://<your s3 bucket>/scripts/wordcount.py s3://<your s3 bucket>/spark-on-eks/outputs/
```

wordcount.py content:
```
import os
import sys
from pyspark.sql import SparkSession
if __name__ == "__main__":
    """
        Usage: wordcount [destination path]
    """
    spark = SparkSession\
        .builder\
        .appName("WordCount")\
        .getOrCreate()
    output_path = None
    if len(sys.argv) > 1:
        output_path = sys.argv[1]
    else:
        print("Job failed. Please provide destination bucket path using entryPointArguments parameter.")
        sys.exit(1)
    region = os.getenv("AWS_REGION")
    text_file = spark.sparkContext.textFile("s3://" + region  + ".elasticmapreduce/emr-containers/samples/wordcount/input")
    counts = text_file.flatMap(lambda line: line.split(" ")).map(lambda word: (word, 1)).reduceByKey(lambda a, b: a + b)
    counts.toDF().write.mode("overwrite").csv(output_path)
    print("WordCount job completed successfully. Refer output at S3 path: " + output_path)
    spark.stop()
```

- Verify the outputs
```
$ aws s3 ls s3://<your s3 bucket>/spark-on-eks/outputs/
2023-01-12 07:43:52          0 _SUCCESS
2023-01-12 07:43:49      72461 part-00000-7818f0f4-1ab3-480f-93c8-067bbe20ea7c-c000.csv
2023-01-12 07:43:47      73573 part-00001-7818f0f4-1ab3-480f-93c8-067bbe20ea7c-c000.csv
2023-01-12 07:43:47      72385 part-00002-7818f0f4-1ab3-480f-93c8-067bbe20ea7c-c000.csv
2023-01-12 07:43:48      74258 part-00003-7818f0f4-1ab3-480f-93c8-067bbe20ea7c-c000.csv
2023-01-12 07:43:51      74146 part-00004-7818f0f4-1ab3-480f-93c8-067bbe20ea7c-c000.csv
2023-01-12 07:43:49      74541 part-00005-7818f0f4-1ab3-480f-93c8-067bbe20ea7c-c000.csv
2023-01-12 07:43:51      74015 part-00006-7818f0f4-1ab3-480f-93c8-067bbe20ea7c-c000.csv
2023-01-12 07:43:50      75077 part-00007-7818f0f4-1ab3-480f-93c8-067bbe20ea7c-c000.csv
2023-01-12 07:43:49      74162 part-00008-7818f0f4-1ab3-480f-93c8-067bbe20ea7c-c000.csv
2023-01-12 07:43:46      74829 part-00009-7818f0f4-1ab3-480f-93c8-067bbe20ea7c-c000.csv
2023-01-12 07:43:50      73035 part-00010-7818f0f4-1ab3-480f-93c8-067bbe20ea7c-c000.csv
2023-01-12 07:43:48      75360 part-00011-7818f0f4-1ab3-480f-93c8-067bbe20ea7c-c000.csv
```

## 4. Auto Submit Job

- Submit task via k8s job
```
apiVersion: v1
kind: List
items:
- apiVersion: batch/v1
  kind: Job
  metadata:
    name: spark-py-job
    namespace: spark
  spec:
    backoffLimit: 0
    completions: 1
    parallelism: 1
    template:
      metadata:
      spec:
        restartPolicy: Never
        serviceAccountName: spark-sa
        securityContext:
          runAsUser: 0
        tolerations:
        - key: "spark-memory-optimized"
          operator: "Exists"
          effect: "NoSchedule"
        containers:
        - args:
          - --master
          - k8s://kubernetes.default.svc
          - --deploy-mode
          - cluster
          - --name
          - spark-python
          - --conf
          - spark.kubernetes.container.image.pullPolicy=Always
          - --conf
          - spark.kubernetes.namespace=spark
          - --conf
          - spark.executor.instances=1 
          - --conf
          - spark.kubernetes.container.image=<your aws account>.dkr.ecr.us-east-1.amazonaws.com/sparkonk8s/spark-py:v3.3.1
          - --conf
          - spark.executor.instances=1
          - --conf
          - spark.executor.memory=2G
          - --conf
          - spark.executor.cores=1
          - --conf
          - spark.kubernetes.driver.podTemplateFile=/opt/spark/conf/driver_pod_template.yml
          - --conf
          - spark.kubernetes.executor.podTemplateFile=/opt/spark/conf/executor_pod_template.yml
          - s3://<your s3 bucket>/scripts/wordcount.py
          - s3://<your s3 bucket>/spark-on-eks/outputs/
          command: ["/opt/spark/bin/spark-submit"]      
          image: <your aws account>.dkr.ecr.us-east-1.amazonaws.com/sparkonk8s/spark-py:v3.3.1
          name: spark-py
          imagePullPolicy: Always
          volumeMounts:
          - name: spark-pod-template
            mountPath: /opt/spark/conf/driver_pod_template.yml
            subPath: driver
          - name: spark-pod-template
            mountPath: /opt/spark/conf/executor_pod_template.yml
            subPath: executor
          - name: spark-defaults
            mountPath: /opt/spark/conf/spark-defaults.conf
            subPath: spark-defaults.conf
        volumes:
        - name: spark-pod-template
          configMap:
           name: spark-eks-pod-template
           defaultMode: 420
        - name: spark-defaults
          configMap:
           name: spark-defaults
           defaultMode: 420
```

## Appendix A. Directly Leveraging EMR Container Image

Previously, it's roughly introduced how to build Spark on EKS, hope it will help understand some details. While if you would like to directly use the [optimized Spark runtime developed by EMR](https://aws.amazon.com/cn/blogs/big-data/run-apache-spark-3-0-workloads-1-7-times-faster-with-amazon-emr-runtime-for-apache-spark/), you could refer to the job below.

- Submit job using EMR image (us-east-1 region)
> Notes: EMR Spark home location is '/usr/lib/spark/'.

```
apiVersion: v1
kind: List
items:
- apiVersion: batch/v1
  kind: Job
  metadata:
    name: spark-py-job
    namespace: spark
  spec:
    backoffLimit: 0
    completions: 1
    parallelism: 1
    template:
      metadata:
      spec:
        restartPolicy: Never
        serviceAccountName: spark-sa
        tolerations:
        - key: "spark-memory-optimized"
          operator: "Exists"
          effect: "NoSchedule"
        containers:
        - args:
          - --master
          - k8s://kubernetes.default.svc
          - --deploy-mode
          - cluster
          - --name
          - spark-python
          - --conf
          - spark.kubernetes.namespace=spark
          - --conf
          - spark.executor.instances=1 
          - --conf
          - spark.kubernetes.container.image=755674844232.dkr.ecr.us-east-1.amazonaws.com/spark/emr-6.9.0:latest
          - --conf
          - spark.executor.instances=1
          - --conf
          - spark.executor.memory=2G
          - --conf
          - spark.executor.cores=1
          - --conf
          - spark.kubernetes.driver.podTemplateFile=/usr/lib/spark/conf/driver_pod_template.yml
          - --conf
          - spark.kubernetes.executor.podTemplateFile=/usr/lib/spark/conf/executor_pod_template.yml
          - --conf
          - spark.kubernetes.driver.podTemplateContainerName=spark-kubernetes-driver
          - --conf
          - spark.kubernetes.executor.podTemplateContainerName=spark-kubernetes-executors
          - --conf
          - spark.kubernetes.authenticate.driver.serviceAccountName=spark-sa
          - --conf
          - spark.kubernetes.authenticate.executor.serviceAccountName=spark-sa
          - s3://<your s3 bucket>/scripts/wordcount.py
          - s3://<your s3 bucket>/spark-on-eks/outputs/
          command: ["/usr/lib/spark/bin/spark-submit"]      
          image: 755674844232.dkr.ecr.us-east-1.amazonaws.com/spark/emr-6.9.0:latest
          name: spark-py
          imagePullPolicy: Always
          volumeMounts:
          - name: spark-pod-template-emr
            mountPath: /usr/lib/spark/conf/driver_pod_template.yml
            subPath: driver
          - name: spark-pod-template-emr
            mountPath: /usr/lib/spark/conf/executor_pod_template.yml
            subPath: executor
        volumes:
        - name: spark-pod-template-emr
          configMap:
           name: spark-eks-pod-template-emr
           defaultMode: 420
```

Config map ark-eks-pod-template-emr:

```
kind: ConfigMap
apiVersion: v1
metadata:
  name: spark-eks-pod-template-emr
  namespace: spark
data:
  driver: |-
    apiVersion: v1
    kind: Pod
    spec:
      tolerations:
        - key: "spark-memory-optimized"
          operator: "Exists"
          effect: "NoSchedule"

  executor: |-
    apiVersion: v1
    kind: Pod
    spec:
      tolerations:
        - key: "spark-memory-optimized"
          operator: "Exists"
          effect: "NoSchedule"
```

To be updated...
