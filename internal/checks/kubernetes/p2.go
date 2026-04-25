package kubernetes

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"github.com/complykit/complykit/internal/engine"
)

// ── etcd encryption at rest ───────────────────────────────────────────────────
// We detect this by checking the kube-apiserver pod args in kube-system.

func (c *Checker) checkEtcdEncryption() []engine.Finding {
	pods, err := c.client.CoreV1().Pods("kube-system").List(context.Background(), metav1.ListOptions{
		LabelSelector: "component=kube-apiserver",
	})
	if err != nil || len(pods.Items) == 0 {
		// Managed clusters (EKS/GKE/AKS) don't expose kube-apiserver pods.
		// Return informational pass — cloud-specific checks cover this.
		return []engine.Finding{pass("k8s_etcd_encryption",
			"kube-apiserver pods not visible (managed cluster) — verify etcd encryption via cloud-provider settings",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("5.4.2"))}
	}
	for _, pod := range pods.Items {
		for _, ct := range pod.Spec.Containers {
			for _, arg := range ct.Args {
				if strings.HasPrefix(arg, "--encryption-provider-config=") {
					return []engine.Finding{pass("k8s_etcd_encryption",
						"kube-apiserver has --encryption-provider-config set",
						soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("5.4.2"))}
				}
			}
		}
	}
	return []engine.Finding{fail(
		"k8s_etcd_encryption",
		"kube-apiserver does not have --encryption-provider-config set — secrets may not be encrypted at rest",
		engine.SeverityHigh,
		"Configure encryption at rest:\n  kube-apiserver --encryption-provider-config=/etc/kubernetes/enc/enc.yaml\n  See: https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/",
		soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("5.4.2"),
	)}
}

// ── OPA Gatekeeper / Kyverno ──────────────────────────────────────────────────

func (c *Checker) checkAdmissionController() []engine.Finding {
	// Check for Gatekeeper: ConstraintTemplate CRD
	_, gatekeeperErr := c.client.Discovery().
		ServerResourcesForGroupVersion("templates.gatekeeper.sh/v1")

	// Check for Kyverno: ClusterPolicy CRD
	_, kyvernoErr := c.client.Discovery().
		ServerResourcesForGroupVersion("kyverno.io/v1")

	if gatekeeperErr == nil {
		return []engine.Finding{pass("k8s_opa_gatekeeper", "OPA Gatekeeper is active (ConstraintTemplate CRDs found)",
			soc2("CC6.6"))}
	}
	if kyvernoErr == nil {
		return []engine.Finding{pass("k8s_opa_gatekeeper", "Kyverno is active (ClusterPolicy CRDs found)",
			soc2("CC6.6"))}
	}

	return []engine.Finding{fail(
		"k8s_opa_gatekeeper",
		"No policy admission controller found (OPA Gatekeeper or Kyverno)",
		engine.SeverityMedium,
		"Install OPA Gatekeeper or Kyverno to enforce policy as code:\n  kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.14/deploy/gatekeeper.yaml\n  # or: helm install kyverno kyverno/kyverno -n kyverno --create-namespace",
		soc2("CC6.6"),
	)}
}

// ── AppArmor profiles ─────────────────────────────────────────────────────────

func (c *Checker) checkAppArmor() []engine.Finding {
	pods, err := c.listPods()
	if err != nil {
		return []engine.Finding{skip("k8s_apparmor", "Kubernetes AppArmor Profiles", err.Error())}
	}
	const annotationPrefix = "container.apparmor.security.beta.kubernetes.io/"
	var noProfile []string
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, ct := range pod.Spec.Containers {
			key := annotationPrefix + ct.Name
			if _, ok := pod.Annotations[key]; !ok {
				noProfile = append(noProfile, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, ct.Name))
			}
		}
	}
	if len(noProfile) == 0 {
		return []engine.Finding{pass("k8s_apparmor", "All workload containers have AppArmor annotations",
			soc2("CC6.6"), cis("5.7.3"))}
	}
	return []engine.Finding{fail(
		"k8s_apparmor",
		fmt.Sprintf("%d container(s) without AppArmor annotation: %v", len(noProfile), truncate(noProfile, 5)),
		engine.SeverityLow,
		"Add AppArmor annotations to pod specs:\n  annotations:\n    container.apparmor.security.beta.kubernetes.io/CONTAINER_NAME: runtime/default",
		soc2("CC6.6"), cis("5.7.3"),
	)}
}

// ── External Secrets Operator ─────────────────────────────────────────────────

func (c *Checker) checkExternalSecrets() []engine.Finding {
	// Check for External Secrets Operator: SecretStore CRD
	_, esoErr := c.client.Discovery().
		ServerResourcesForGroupVersion("external-secrets.io/v1beta1")

	// Check for CSI Secret Store daemonsets
	dsList, err := c.client.AppsV1().DaemonSets("").List(context.Background(), metav1.ListOptions{})
	if err == nil {
		for _, ds := range dsList.Items {
			name := strings.ToLower(ds.Name)
			if strings.Contains(name, "secrets-store") || strings.Contains(name, "csi-secrets") {
				return []engine.Finding{pass("k8s_external_secrets",
					fmt.Sprintf("Secrets Store CSI Driver found: %s/%s", ds.Namespace, ds.Name),
					soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"))}
			}
		}
	}

	if esoErr == nil {
		return []engine.Finding{pass("k8s_external_secrets",
			"External Secrets Operator is active (SecretStore CRDs found)",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"))}
	}

	return []engine.Finding{fail(
		"k8s_external_secrets",
		"No external secret management found (External Secrets Operator or CSI Secrets Store Driver)",
		engine.SeverityMedium,
		"Install External Secrets Operator to sync secrets from AWS/GCP/Azure:\n  helm install external-secrets external-secrets/external-secrets -n external-secrets --create-namespace\n  # or: install Secrets Store CSI Driver",
		soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"),
	)}
}

// ── Kubernetes audit logging (P3) ─────────────────────────────────────────────

func (c *Checker) checkAuditLogging() []engine.Finding {
	pods, err := c.client.CoreV1().Pods("kube-system").List(context.Background(), metav1.ListOptions{
		LabelSelector: "component=kube-apiserver",
	})
	if err != nil || len(pods.Items) == 0 {
		return []engine.Finding{pass("k8s_audit_logging",
			"kube-apiserver not visible (managed cluster) — audit logging managed by cloud provider",
			soc2("CC7.2"), hipaa("164.312(b)"), cis("3.2.1"))}
	}
	for _, pod := range pods.Items {
		for _, ct := range pod.Spec.Containers {
			for _, arg := range ct.Args {
				if strings.HasPrefix(arg, "--audit-log-path=") || strings.HasPrefix(arg, "--audit-policy-file=") {
					return []engine.Finding{pass("k8s_audit_logging",
						"Kubernetes audit logging is configured on kube-apiserver",
						soc2("CC7.2"), hipaa("164.312(b)"), cis("3.2.1"))}
				}
			}
		}
	}
	return []engine.Finding{fail(
		"k8s_audit_logging",
		"kube-apiserver does not have audit logging configured",
		engine.SeverityHigh,
		"Configure audit logging:\n  kube-apiserver --audit-log-path=/var/log/audit.log --audit-policy-file=/etc/kubernetes/audit-policy.yaml --audit-log-maxage=30 --audit-log-maxbackup=10",
		soc2("CC7.2"), hipaa("164.312(b)"), cis("3.2.1"),
	)}
}

// ── Falco runtime threat detection (P3) ──────────────────────────────────────

func (c *Checker) checkFalco() []engine.Finding {
	// Check for Falco daemonset across all namespaces
	dsList, err := c.client.AppsV1().DaemonSets("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return []engine.Finding{skip("k8s_falco", "Falco Runtime Detection", err.Error())}
	}
	for _, ds := range dsList.Items {
		if strings.Contains(strings.ToLower(ds.Name), "falco") {
			return []engine.Finding{pass("k8s_falco",
				fmt.Sprintf("Falco runtime threat detection is running: %s/%s", ds.Namespace, ds.Name),
				soc2("CC6.8"), hipaa("164.308(a)(1)(ii)(D)"))}
		}
	}
	return []engine.Finding{fail(
		"k8s_falco",
		"Falco runtime threat detection not found in cluster",
		engine.SeverityMedium,
		"Install Falco for runtime security monitoring:\n  helm install falco falcosecurity/falco --namespace falco --create-namespace",
		soc2("CC6.8"), hipaa("164.308(a)(1)(ii)(D)"),
	)}
}
