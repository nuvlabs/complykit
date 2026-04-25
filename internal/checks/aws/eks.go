package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/complykit/complykit/internal/engine"
)

type EKSChecker struct {
	client *eks.Client
}

func NewEKSChecker(cfg aws.Config) *EKSChecker {
	return &EKSChecker{client: eks.NewFromConfig(cfg)}
}

func (c *EKSChecker) Integration() string { return "AWS/EKS" }

func (c *EKSChecker) Run() ([]engine.Finding, error) {
	clusters, err := c.listClusters()
	if err != nil {
		return []engine.Finding{skip("aws_eks", "AWS EKS Clusters", err.Error())}, nil
	}
	if len(clusters) == 0 {
		return []engine.Finding{pass("aws_eks_no_clusters", "No EKS clusters found", "AWS/EKS", "account",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("5.1.1"))}, nil
	}

	var findings []engine.Finding
	for _, name := range clusters {
		cluster, err := c.client.DescribeCluster(context.Background(), &eks.DescribeClusterInput{
			Name: aws.String(name),
		})
		if err != nil {
			findings = append(findings, skip("aws_eks_"+name, "EKS Cluster "+name, err.Error()))
			continue
		}
		findings = append(findings, c.checkEndpointAccess(cluster.Cluster)...)
		findings = append(findings, c.checkSecretsEncryption(cluster.Cluster)...)
		findings = append(findings, c.checkLogging(cluster.Cluster)...)
		findings = append(findings, c.checkNodeGroups(name)...)
	}
	return findings, nil
}

func (c *EKSChecker) checkEndpointAccess(cl *ekstypes.Cluster) []engine.Finding {
	name := aws.ToString(cl.Name)
	if cl.ResourcesVpcConfig == nil {
		return nil
	}
	publicAccess := cl.ResourcesVpcConfig.EndpointPublicAccess
	publicCIDRs := cl.ResourcesVpcConfig.PublicAccessCidrs

	// Public endpoint is OK only if locked to specific CIDRs (not 0.0.0.0/0)
	if publicAccess {
		for _, cidr := range publicCIDRs {
			if cidr == "0.0.0.0/0" {
				return []engine.Finding{fail(
					"aws_eks_endpoint_public",
					fmt.Sprintf("EKS cluster %q API endpoint is public to 0.0.0.0/0", name),
					"AWS/EKS", name, SeverityCritical,
					"Restrict API endpoint access:\n  aws eks update-cluster-config --name "+name+" --resources-vpc-config endpointPublicAccess=true,publicAccessCidrs=YOUR_IP/32,endpointPrivateAccess=true",
					soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("5.4.1"),
				)}
			}
		}
	}
	return []engine.Finding{pass("aws_eks_endpoint_public",
		fmt.Sprintf("EKS cluster %q API endpoint access is restricted", name),
		"AWS/EKS", name, soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("5.4.1"))}
}

func (c *EKSChecker) checkSecretsEncryption(cl *ekstypes.Cluster) []engine.Finding {
	name := aws.ToString(cl.Name)
	for _, cfg := range cl.EncryptionConfig {
		for _, res := range cfg.Resources {
			if res == "secrets" {
				return []engine.Finding{pass("aws_eks_secrets_encryption",
					fmt.Sprintf("EKS cluster %q has secrets envelope encryption enabled", name),
					"AWS/EKS", name, soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("5.3.1"))}
			}
		}
	}
	return []engine.Finding{fail(
		"aws_eks_secrets_encryption",
		fmt.Sprintf("EKS cluster %q does not have secrets envelope encryption enabled", name),
		"AWS/EKS", name, SeverityHigh,
		"Enable envelope encryption for Kubernetes secrets:\n  aws eks associate-encryption-config --cluster-name "+name+" --encryption-config '[{\"resources\":[\"secrets\"],\"provider\":{\"keyArn\":\"YOUR_KMS_ARN\"}}]'",
		soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("5.3.1"),
	)}
}

func (c *EKSChecker) checkLogging(cl *ekstypes.Cluster) []engine.Finding {
	name := aws.ToString(cl.Name)
	if cl.Logging == nil {
		return []engine.Finding{fail(
			"aws_eks_logging",
			fmt.Sprintf("EKS cluster %q has no control plane logging configured", name),
			"AWS/EKS", name, SeverityHigh,
			"Enable control plane logging:\n  aws eks update-cluster-config --name "+name+" --logging '{\"clusterLogging\":[{\"types\":[\"api\",\"audit\",\"authenticator\",\"controllerManager\",\"scheduler\"],\"enabled\":true}]}'",
			soc2("CC7.2"), hipaa("164.312(b)"), cis("5.1.1"),
		)}
	}

	enabledTypes := map[string]bool{}
	for _, setup := range cl.Logging.ClusterLogging {
		if aws.ToBool(setup.Enabled) {
			for _, t := range setup.Types {
				enabledTypes[string(t)] = true
			}
		}
	}

	required := []string{"api", "audit", "authenticator"}
	var missing []string
	for _, r := range required {
		if !enabledTypes[r] {
			missing = append(missing, r)
		}
	}
	if len(missing) == 0 {
		return []engine.Finding{pass("aws_eks_logging",
			fmt.Sprintf("EKS cluster %q has required control plane logs enabled", name),
			"AWS/EKS", name, soc2("CC7.2"), hipaa("164.312(b)"), cis("5.1.1"))}
	}
	return []engine.Finding{fail(
		"aws_eks_logging",
		fmt.Sprintf("EKS cluster %q missing log types: %v", name, missing),
		"AWS/EKS", name, SeverityMedium,
		"Enable missing log types:\n  aws eks update-cluster-config --name "+name+" --logging '{\"clusterLogging\":[{\"types\":[\"api\",\"audit\",\"authenticator\",\"controllerManager\",\"scheduler\"],\"enabled\":true}]}'",
		soc2("CC7.2"), hipaa("164.312(b)"), cis("5.1.1"),
	)}
}

func (c *EKSChecker) checkNodeGroups(clusterName string) []engine.Finding {
	ngs, err := c.client.ListNodegroups(context.Background(), &eks.ListNodegroupsInput{
		ClusterName: aws.String(clusterName),
	})
	if err != nil {
		return nil
	}

	var noIMDS []string
	for _, ng := range ngs.Nodegroups {
		detail, err := c.client.DescribeNodegroup(context.Background(), &eks.DescribeNodegroupInput{
			ClusterName:   aws.String(clusterName),
			NodegroupName: aws.String(ng),
		})
		if err != nil {
			continue
		}
		if detail.Nodegroup.LaunchTemplate == nil {
			// no custom launch template — check if IMDS v2 is enforced via nodegroup config
			// nodegroups without custom LT default to IMDSv1 accessible
			noIMDS = append(noIMDS, ng)
		}
	}

	if len(noIMDS) == 0 {
		return []engine.Finding{pass("aws_eks_imdsv2",
			fmt.Sprintf("EKS cluster %q node groups use custom launch templates", clusterName),
			"AWS/EKS", clusterName, soc2("CC6.6"), cis("5.4.2"))}
	}
	return []engine.Finding{fail(
		"aws_eks_imdsv2",
		fmt.Sprintf("EKS cluster %q has %d node group(s) without custom launch template (IMDSv2 not enforced): %v",
			clusterName, len(noIMDS), noIMDS),
		"AWS/EKS", clusterName, SeverityMedium,
		"Use a custom launch template to enforce IMDSv2:\n  Set HttpTokens=required in the launch template metadata options",
		soc2("CC6.6"), cis("5.4.2"),
	)}
}

func (c *EKSChecker) listClusters() ([]string, error) {
	var names []string
	paginator := eks.NewListClustersPaginator(c.client, &eks.ListClustersInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return nil, err
		}
		names = append(names, page.Clusters...)
	}
	return names, nil
}
