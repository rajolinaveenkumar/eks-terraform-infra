resource "aws_key_pair" "eks" {
  key_name   = "myec2-key-eks"
  public_key = file("~/.ssh/myec2keyeks.pub")
}



# IAM Role for EKS Cluster
resource "aws_iam_role" "eks_cluster_role" {
  name_prefix = "${var.project_name}-eks-cluster-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "eks.amazonaws.com"
      }
      Action = ["sts:AssumeRole", "sts:TagSession"]
      Sid    = "EKSClusterAssumeRole"
    }]
  })
  
  tags = merge(
    var.common_tags,
    {
      Name = "${var.project_name}-${var.environment}"
    }
  )
}

resource "aws_iam_role_policy_attachment" "eks_cluster_AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster_role.name
}

resource "aws_iam_role_policy_attachment" "eks_cluster_AmazonEKSVPCResourceController" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.eks_cluster_role.name
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "eks_log_group" {
  name              = "/aws/eks/${var.project_name}/cluster"
  retention_in_days = 90
  
  tags = merge(
    var.common_tags,
    {
      Name = "${var.project_name}-${var.environment}"
    }
  )
}

# KMS Key
resource "aws_kms_key" "eks" {
  description         = "${var.project_name} cluster encryption key"
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.kms_policy.json
  
  tags = merge(
    var.common_tags,
    {
      Name = "${var.project_name}-${var.environment}"
    }
  )
}

resource "aws_kms_alias" "eks" {
  name          = "alias/eks/${var.project_name}"
  target_key_id = aws_kms_key.eks.key_id
}

data "aws_iam_policy_document" "kms_policy" {
  statement {
    sid       = "Default"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::343430925817:root"]
    }
  }
  statement {
    sid       = "KeyUsage"
    actions   = [
      "kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*",
      "kms:DescribeKey", "kms:ReEncrypt*"
    ]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::343430925817:user/naveen"]
    }
  }
}

# EKS Cluster
resource "aws_eks_cluster" "this" {
  name     = var.project_name
  role_arn = aws_iam_role.eks_cluster_role.arn
  version  = var.eks_version

  vpc_config {
    subnet_ids              = local.private_subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = false
    public_access_cidrs     = ["0.0.0.0/0"]
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator"]
  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = aws_kms_key.eks.arn
    }
  }
  tags = merge(
    var.common_tags,
    {
      Name = "${var.project_name}-${var.environment}"
      terraform-aws-modules = "eks"
    }
  )

}

# Addons
locals {
  addons = ["coredns", "kube-proxy", "vpc-cni", "metrics-server", "eks-pod-identity-agent"]
}

resource "aws_eks_addon" "addons" {
  for_each = toset(local.addons)
  cluster_name = aws_eks_cluster.this.name
  
  addon_name                 = each.key
  addon_version              = data.aws_eks_addon_version.latest[each.key].version
  preserve                   = true
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
  tags = merge(
    var.common_tags,
    {
      Name = "${var.project_name}-${var.environment}"
    }
  )
}

data "aws_eks_addon_version" "latest" {
  for_each = toset(local.addons)

  addon_name         = each.key
  kubernetes_version = var.eks_version
}

# IAM Role for Node Group
resource "aws_iam_role" "node_group_role" {
  name_prefix = "${var.project_name}-node-group-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })

 tags = merge(
    var.common_tags,
    {
      Name = "${var.project_name}-${var.environment}"
    }
  )
}

resource "aws_iam_role_policy_attachment" "node_group_policies" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy",
    "arn:aws:iam::aws:policy/service-role/AmazonEFSCSIDriverPolicy",
    "arn:aws:iam::aws:policy/ElasticLoadBalancingFullAccess"
  ])

  policy_arn = each.key
  role       = aws_iam_role.node_group_role.name
}

# Blue Node Group
resource "aws_eks_node_group" "blue" {
 
  node_group_name = "blue"
  node_role_arn   = aws_iam_role.node_group_role.arn
  subnet_ids      = local.private_subnet_ids
  instance_types  = ["m5.xlarge"]
  version         = var.eks_version
  cluster_name = aws_eks_cluster.this.name

  scaling_config {
    desired_size = 2
    max_size     = 10
    min_size     = 2
  }

  update_config {
    max_unavailable_percentage = 33
  }

  tags = merge(
    var.common_tags,
    {
      Name = "blue"
    }
  )
}

# Outputs can be added as needed
