package kubernetes

import (
	"context"
	"fmt"
	"os"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"github.com/complykit/complykit/internal/engine"
)

func (c *Checker) checkNoLatestTag() []engine.Finding {
	pods, err := c.listPods()
	if err != nil {
		return []engine.Finding{skip("k8s_image_pull_always", "Kubernetes Image Tag Policy", err.Error())}
	}
	var flagged []string
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, ct := range append(pod.Spec.Containers, pod.Spec.InitContainers...) {
			img := ct.Image
			// flag :latest or no tag at all
			if strings.HasSuffix(img, ":latest") || (!strings.Contains(img, ":") && !strings.Contains(img, "@")) {
				flagged = append(flagged, fmt.Sprintf("%s/%s/%s (%s)", pod.Namespace, pod.Name, ct.Name, img))
			}
		}
	}
	if len(flagged) == 0 {
		return []engine.Finding{pass("k8s_image_pull_always", "No containers using :latest or untagged images",
			soc2("CC7.1"), cis("5.5.1"))}
	}
	return []engine.Finding{fail(
		"k8s_image_pull_always",
		fmt.Sprintf("%d container(s) using :latest or untagged images: %v", len(flagged), truncate(flagged, 5)),
		engine.SeverityMedium,
		"Pin images to a specific digest or immutable tag:\n  image: myrepo/myapp@sha256:abc123...\n  # or: image: myrepo/myapp:v1.2.3",
		soc2("CC7.1"), cis("5.5.1"),
	)}
}

func (c *Checker) checkNonRootUID() []engine.Finding {
	pods, err := c.listPods()
	if err != nil {
		return []engine.Finding{skip("k8s_non_root_uid", "Kubernetes Non-Root UID", err.Error())}
	}
	var flagged []string
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, ct := range append(pod.Spec.Containers, pod.Spec.InitContainers...) {
			if ct.SecurityContext != nil && ct.SecurityContext.RunAsUser != nil && *ct.SecurityContext.RunAsUser == 0 {
				flagged = append(flagged, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, ct.Name))
			}
		}
	}
	if len(flagged) == 0 {
		return []engine.Finding{pass("k8s_non_root_uid", "No containers explicitly run as UID 0",
			soc2("CC6.6"), hipaa("164.312(a)(1)"), cis("5.2.6"))}
	}
	return []engine.Finding{fail(
		"k8s_non_root_uid",
		fmt.Sprintf("%d container(s) running as UID 0: %v", len(flagged), truncate(flagged, 5)),
		engine.SeverityHigh,
		"Set a non-zero UID:\n  securityContext:\n    runAsUser: 1000\n    runAsNonRoot: true",
		soc2("CC6.6"), hipaa("164.312(a)(1)"), cis("5.2.6"),
	)}
}

func (c *Checker) checkResourceRequests() []engine.Finding {
	pods, err := c.listPods()
	if err != nil {
		return []engine.Finding{skip("k8s_resource_requests", "Kubernetes Resource Requests", err.Error())}
	}
	var noRequests []string
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, ct := range pod.Spec.Containers {
			if ct.Resources.Requests == nil || len(ct.Resources.Requests) == 0 {
				noRequests = append(noRequests, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, ct.Name))
			}
		}
	}
	if len(noRequests) == 0 {
		return []engine.Finding{pass("k8s_resource_requests", "All workload containers have resource requests set",
			soc2("CC6.6"), cis("5.1.3"))}
	}
	return []engine.Finding{fail(
		"k8s_resource_requests",
		fmt.Sprintf("%d container(s) without resource requests: %v", len(noRequests), truncate(noRequests, 5)),
		engine.SeverityMedium,
		"Set CPU and memory requests on all containers:\n  resources:\n    requests:\n      cpu: \"100m\"\n      memory: \"128Mi\"",
		soc2("CC6.6"), cis("5.1.3"),
	)}
}

func (c *Checker) checkImageRegistry() []engine.Finding {
	allowedRaw := os.Getenv("ALLOWED_REGISTRIES")
	if allowedRaw == "" {
		// Skip if no allowlist configured — no false positives
		return []engine.Finding{skip("k8s_image_registry",
			"Kubernetes Image Registry Allowlist",
			"Set ALLOWED_REGISTRIES env var (comma-separated prefixes) to enable this check")}
	}
	allowed := strings.Split(allowedRaw, ",")
	for i, r := range allowed {
		allowed[i] = strings.TrimSpace(r)
	}

	pods, err := c.listPods()
	if err != nil {
		return []engine.Finding{skip("k8s_image_registry", "Kubernetes Image Registry Allowlist", err.Error())}
	}

	var flagged []string
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, ct := range append(pod.Spec.Containers, pod.Spec.InitContainers...) {
			if !imageFromAllowed(ct.Image, allowed) {
				flagged = append(flagged, fmt.Sprintf("%s/%s/%s (%s)", pod.Namespace, pod.Name, ct.Name, ct.Image))
			}
		}
	}
	if len(flagged) == 0 {
		return []engine.Finding{pass("k8s_image_registry",
			fmt.Sprintf("All container images are from allowed registries (%v)", allowed),
			soc2("CC7.1"), cis("5.5.1"))}
	}
	return []engine.Finding{fail(
		"k8s_image_registry",
		fmt.Sprintf("%d container(s) using images from unapproved registries: %v", len(flagged), truncate(flagged, 5)),
		engine.SeverityHigh,
		fmt.Sprintf("Only use images from approved registries: %v\n  Consider using OPA/Kyverno to enforce this policy.", allowed),
		soc2("CC7.1"), cis("5.5.1"),
	)}
}

func imageFromAllowed(image string, allowed []string) bool {
	for _, prefix := range allowed {
		if strings.HasPrefix(image, prefix) {
			return true
		}
	}
	return false
}

// checkNamespacesHaveResourceQuotas ensures LimitRanges/ResourceQuotas exist
func (c *Checker) checkNamespaceResourceQuotas() []engine.Finding {
	namespaces, err := c.client.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return []engine.Finding{skip("k8s_namespace_quotas", "Kubernetes Namespace Resource Quotas", err.Error())}
	}
	var noQuota []string
	for _, ns := range namespaces.Items {
		if isSystemNamespace(ns.Name) {
			continue
		}
		quotas, _ := c.client.CoreV1().ResourceQuotas(ns.Name).List(context.Background(), metav1.ListOptions{})
		if quotas == nil || len(quotas.Items) == 0 {
			noQuota = append(noQuota, ns.Name)
		}
	}
	if len(noQuota) == 0 {
		return []engine.Finding{pass("k8s_namespace_quotas", "All workload namespaces have ResourceQuotas",
			soc2("CC6.6"))}
	}
	return []engine.Finding{fail(
		"k8s_namespace_quotas",
		fmt.Sprintf("%d namespace(s) without ResourceQuota: %v", len(noQuota), truncate(noQuota, 5)),
		engine.SeverityLow,
		"Add ResourceQuota to prevent resource exhaustion:\n  kubectl create quota my-quota --hard=cpu=4,memory=8Gi,pods=20 -n NAMESPACE",
		soc2("CC6.6"),
	)}
}
