package kubernetes

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/complykit/complykit/internal/engine"
)

type Checker struct {
	client     kubernetes.Interface
	kubeconfig string
}

func NewCheckerFromKubeconfig(kubeconfig string) (*Checker, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		rules, &clientcmd.ConfigOverrides{},
	).ClientConfig()
	if err != nil {
		return nil, err
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Checker{client: client, kubeconfig: kubeconfig}, nil
}

func NewCheckerFromEnv() *Checker {
	c, err := NewCheckerFromKubeconfig("")
	if err != nil {
		return nil
	}
	// quick connectivity test
	_, err = c.client.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{Limit: 1})
	if err != nil {
		return nil
	}
	return c
}

func (c *Checker) Integration() string { return "Kubernetes" }

func (c *Checker) Run() ([]engine.Finding, error) {
	var findings []engine.Finding
	// Pod/container security
	findings = append(findings, c.checkPrivilegedContainers()...)
	findings = append(findings, c.checkRootContainers()...)
	findings = append(findings, c.checkHostNamespaceSharingContainers()...)
	findings = append(findings, c.checkResourceLimits()...)
	findings = append(findings, c.checkReadOnlyRootFS()...)
	findings = append(findings, c.checkPrivilegeEscalation()...)
	findings = append(findings, c.checkCapabilityDrop()...)
	findings = append(findings, c.checkHostPathMounts()...)
	findings = append(findings, c.checkSeccompProfiles()...)
	findings = append(findings, c.checkSecretsInEnvVars()...)
	// RBAC
	findings = append(findings, c.checkClusterAdminBindings()...)
	findings = append(findings, c.checkWildcardRoles()...)
	findings = append(findings, c.checkSATokenAutomount()...)
	findings = append(findings, c.checkBindEscalateRoles()...)
	// Networking
	findings = append(findings, c.checkNetworkPolicies()...)
	findings = append(findings, c.checkDefaultDenyNetworkPolicies()...)
	// Admission
	findings = append(findings, c.checkPodSecurityAdmission()...)
	// P1 additions
	findings = append(findings, c.checkNoLatestTag()...)
	findings = append(findings, c.checkNonRootUID()...)
	findings = append(findings, c.checkResourceRequests()...)
	findings = append(findings, c.checkImageRegistry()...)
	findings = append(findings, c.checkNamespaceResourceQuotas()...)
	// P2 additions
	findings = append(findings, c.checkEtcdEncryption()...)
	findings = append(findings, c.checkAdmissionController()...)
	findings = append(findings, c.checkAppArmor()...)
	findings = append(findings, c.checkExternalSecrets()...)
	// P3 additions
	findings = append(findings, c.checkAuditLogging()...)
	findings = append(findings, c.checkFalco()...)
	// Database security
	findings = append(findings, c.checkDBPVCEncryption()...)
	findings = append(findings, c.checkDBNoPublicService()...)
	findings = append(findings, c.checkDBNotRoot()...)
	findings = append(findings, c.checkDBSecretNotConfigMap()...)
	findings = append(findings, c.checkDBAuditLogging()...)
	return findings, nil
}

func (c *Checker) listPods() ([]corev1.Pod, error) {
	var pods []corev1.Pod
	var continueToken string
	for {
		list, err := c.client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
			Limit:    500,
			Continue: continueToken,
		})
		if err != nil {
			return nil, err
		}
		pods = append(pods, list.Items...)
		if list.Continue == "" {
			break
		}
		continueToken = list.Continue
	}
	return pods, nil
}

// ── Privileged containers ─────────────────────────────────────────────────────

func (c *Checker) checkPrivilegedContainers() []engine.Finding {
	pods, err := c.listPods()
	if err != nil {
		return []engine.Finding{skip("k8s_privileged", "Kubernetes Privileged Containers", err.Error())}
	}

	var flagged []string
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, ct := range append(pod.Spec.Containers, pod.Spec.InitContainers...) {
			if ct.SecurityContext != nil && ct.SecurityContext.Privileged != nil && *ct.SecurityContext.Privileged {
				flagged = append(flagged, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, ct.Name))
			}
		}
	}

	if len(flagged) == 0 {
		return []engine.Finding{pass("k8s_privileged", "No privileged containers found in workload namespaces",
			soc2("CC6.6"), hipaa("164.312(a)(1)"), cis("5.2.1"))}
	}
	return []engine.Finding{fail(
		"k8s_privileged",
		fmt.Sprintf("%d privileged container(s) found: %v", len(flagged), truncate(flagged, 5)),
		engine.SeverityCritical,
		"Remove privileged:true from container securityContext. Use specific capabilities instead:\n  securityContext:\n    privileged: false\n    capabilities:\n      add: [NET_ADMIN]  # only what's needed",
		soc2("CC6.6"), hipaa("164.312(a)(1)"), cis("5.2.1"),
	)}
}

// ── Root containers ───────────────────────────────────────────────────────────

func (c *Checker) checkRootContainers() []engine.Finding {
	pods, err := c.listPods()
	if err != nil {
		return []engine.Finding{skip("k8s_root_user", "Kubernetes Root Containers", err.Error())}
	}

	var flagged []string
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		podRunsAsRoot := pod.Spec.SecurityContext != nil &&
			pod.Spec.SecurityContext.RunAsNonRoot != nil &&
			!*pod.Spec.SecurityContext.RunAsNonRoot

		for _, ct := range append(pod.Spec.Containers, pod.Spec.InitContainers...) {
			runsAsRoot := podRunsAsRoot
			if ct.SecurityContext != nil {
				if ct.SecurityContext.RunAsNonRoot != nil {
					runsAsRoot = !*ct.SecurityContext.RunAsNonRoot
				}
				if ct.SecurityContext.RunAsUser != nil && *ct.SecurityContext.RunAsUser == 0 {
					runsAsRoot = true
				}
			}
			if runsAsRoot {
				flagged = append(flagged, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, ct.Name))
			}
		}
	}

	if len(flagged) == 0 {
		return []engine.Finding{pass("k8s_root_user", "No containers explicitly configured to run as root",
			soc2("CC6.6"), hipaa("164.312(a)(1)"), cis("5.2.6"))}
	}
	return []engine.Finding{fail(
		"k8s_root_user",
		fmt.Sprintf("%d container(s) configured to run as root: %v", len(flagged), truncate(flagged, 5)),
		engine.SeverityHigh,
		"Set runAsNonRoot: true in container securityContext:\n  securityContext:\n    runAsNonRoot: true\n    runAsUser: 1000",
		soc2("CC6.6"), hipaa("164.312(a)(1)"), cis("5.2.6"),
	)}
}

// ── Host namespace sharing ────────────────────────────────────────────────────

func (c *Checker) checkHostNamespaceSharingContainers() []engine.Finding {
	pods, err := c.listPods()
	if err != nil {
		return []engine.Finding{skip("k8s_host_namespace", "Kubernetes Host Namespace Sharing", err.Error())}
	}

	var hostNet, hostPID, hostIPC []string
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		label := pod.Namespace + "/" + pod.Name
		if pod.Spec.HostNetwork {
			hostNet = append(hostNet, label)
		}
		if pod.Spec.HostPID {
			hostPID = append(hostPID, label)
		}
		if pod.Spec.HostIPC {
			hostIPC = append(hostIPC, label)
		}
	}

	var findings []engine.Finding
	for _, check := range []struct {
		id, title string
		items     []string
		cis       string
	}{
		{"k8s_host_network", "hostNetwork", hostNet, "5.2.4"},
		{"k8s_host_pid", "hostPID", hostPID, "5.2.2"},
		{"k8s_host_ipc", "hostIPC", hostIPC, "5.2.3"},
	} {
		if len(check.items) == 0 {
			findings = append(findings, pass(check.id,
				fmt.Sprintf("No pods use %s in workload namespaces", check.title),
				soc2("CC6.6"), hipaa("164.312(a)(1)"), cis(check.cis)))
		} else {
			findings = append(findings, fail(
				check.id,
				fmt.Sprintf("%d pod(s) use %s: %v", len(check.items), check.title, truncate(check.items, 5)),
				engine.SeverityHigh,
				fmt.Sprintf("Remove %s: true from pod spec unless absolutely required.", check.title),
				soc2("CC6.6"), hipaa("164.312(a)(1)"), cis(check.cis),
			))
		}
	}
	return findings
}

// ── Resource limits ───────────────────────────────────────────────────────────

func (c *Checker) checkResourceLimits() []engine.Finding {
	pods, err := c.listPods()
	if err != nil {
		return []engine.Finding{skip("k8s_resource_limits", "Kubernetes Resource Limits", err.Error())}
	}

	var noLimits []string
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, ct := range pod.Spec.Containers {
			if ct.Resources.Limits == nil || len(ct.Resources.Limits) == 0 {
				noLimits = append(noLimits, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, ct.Name))
			}
		}
	}

	if len(noLimits) == 0 {
		return []engine.Finding{pass("k8s_resource_limits", "All workload containers have resource limits set",
			soc2("CC6.6"), cis("5.2.12"))}
	}
	return []engine.Finding{fail(
		"k8s_resource_limits",
		fmt.Sprintf("%d container(s) without resource limits: %v", len(noLimits), truncate(noLimits, 5)),
		engine.SeverityMedium,
		"Set CPU and memory limits on all containers:\n  resources:\n    limits:\n      cpu: \"500m\"\n      memory: \"256Mi\"",
		soc2("CC6.6"), cis("5.2.12"),
	)}
}

// ── Read-only root filesystem ─────────────────────────────────────────────────

func (c *Checker) checkReadOnlyRootFS() []engine.Finding {
	pods, err := c.listPods()
	if err != nil {
		return []engine.Finding{skip("k8s_readonly_rootfs", "Kubernetes Read-Only Root Filesystem", err.Error())}
	}

	var writable []string
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, ct := range pod.Spec.Containers {
			if ct.SecurityContext == nil || ct.SecurityContext.ReadOnlyRootFilesystem == nil || !*ct.SecurityContext.ReadOnlyRootFilesystem {
				writable = append(writable, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, ct.Name))
			}
		}
	}

	if len(writable) == 0 {
		return []engine.Finding{pass("k8s_readonly_rootfs", "All workload containers use read-only root filesystem",
			soc2("CC6.6"), hipaa("164.312(a)(1)"), cis("5.2.8"))}
	}
	return []engine.Finding{fail(
		"k8s_readonly_rootfs",
		fmt.Sprintf("%d container(s) without read-only root filesystem: %v", len(writable), truncate(writable, 5)),
		engine.SeverityMedium,
		"Enable read-only root filesystem:\n  securityContext:\n    readOnlyRootFilesystem: true\n  (mount writable volumes for paths that need writes)",
		soc2("CC6.6"), hipaa("164.312(a)(1)"), cis("5.2.8"),
	)}
}

// ── Cluster-admin bindings ────────────────────────────────────────────────────

func (c *Checker) checkClusterAdminBindings() []engine.Finding {
	bindings, err := c.client.RbacV1().ClusterRoleBindings().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return []engine.Finding{skip("k8s_cluster_admin", "Kubernetes Cluster-Admin Bindings", err.Error())}
	}

	var overGranted []string
	for _, crb := range bindings.Items {
		if crb.RoleRef.Name != "cluster-admin" {
			continue
		}
		for _, subject := range crb.Subjects {
			if subject.Kind == rbacv1.ServiceAccountKind && isSystemNamespace(subject.Namespace) {
				continue
			}
			if strings.HasPrefix(subject.Name, "system:") {
				continue
			}
			overGranted = append(overGranted, fmt.Sprintf("%s→%s/%s", crb.Name, subject.Kind, subject.Name))
		}
	}

	if len(overGranted) == 0 {
		return []engine.Finding{pass("k8s_cluster_admin", "No unexpected cluster-admin bindings found",
			soc2("CC6.3"), hipaa("164.308(a)(3)(i)"), cis("5.1.1"))}
	}
	return []engine.Finding{fail(
		"k8s_cluster_admin",
		fmt.Sprintf("%d non-system cluster-admin binding(s): %v", len(overGranted), truncate(overGranted, 5)),
		engine.SeverityHigh,
		"Replace cluster-admin bindings with least-privilege roles:\n  kubectl delete clusterrolebinding BINDING_NAME\n  kubectl create clusterrolebinding NAME --clusterrole=VIEW_ONLY_ROLE --user=USER",
		soc2("CC6.3"), hipaa("164.308(a)(3)(i)"), cis("5.1.1"),
	)}
}

// ── Network Policies ──────────────────────────────────────────────────────────

func (c *Checker) checkNetworkPolicies() []engine.Finding {
	namespaces, err := c.client.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return []engine.Finding{skip("k8s_network_policies", "Kubernetes Network Policies", err.Error())}
	}

	var noPolicy []string
	for _, ns := range namespaces.Items {
		if isSystemNamespace(ns.Name) {
			continue
		}
		policies, err := c.client.NetworkingV1().NetworkPolicies(ns.Name).List(context.Background(), metav1.ListOptions{})
		if err != nil || len(policies.Items) == 0 {
			noPolicy = append(noPolicy, ns.Name)
		}
	}

	if len(noPolicy) == 0 {
		return []engine.Finding{pass("k8s_network_policies", "All workload namespaces have network policies",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("5.3.2"))}
	}
	return []engine.Finding{fail(
		"k8s_network_policies",
		fmt.Sprintf("%d namespace(s) without network policies: %v", len(noPolicy), truncate(noPolicy, 5)),
		engine.SeverityMedium,
		"Add a default-deny network policy to each namespace:\n  apiVersion: networking.k8s.io/v1\n  kind: NetworkPolicy\n  metadata:\n    name: default-deny-all\n  spec:\n    podSelector: {}\n    policyTypes: [Ingress, Egress]",
		soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("5.3.2"),
	)}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func isSystemNamespace(ns string) bool {
	return ns == "kube-system" || ns == "kube-public" || ns == "kube-node-lease"
}

func pass(id, title string, controls ...engine.ControlRef) engine.Finding {
	return engine.Finding{CheckID: id, Title: title, Status: engine.StatusPass, Integration: "Kubernetes", Controls: controls}
}
func fail(id, title string, severity engine.Severity, remediation string, controls ...engine.ControlRef) engine.Finding {
	return engine.Finding{CheckID: id, Title: title, Status: engine.StatusFail, Severity: severity, Integration: "Kubernetes", Remediation: remediation, Controls: controls}
}
func skip(id, title, detail string) engine.Finding {
	return engine.Finding{CheckID: id, Title: title, Status: engine.StatusSkip, Integration: "Kubernetes", Detail: detail}
}
func soc2(id string) engine.ControlRef  { return engine.ControlRef{Framework: engine.FrameworkSOC2, ID: id} }
func hipaa(id string) engine.ControlRef { return engine.ControlRef{Framework: engine.FrameworkHIPAA, ID: id} }
func cis(id string) engine.ControlRef   { return engine.ControlRef{Framework: engine.FrameworkCIS, ID: id} }
func truncate(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:max], ", ") + fmt.Sprintf(" +%d more", len(items)-max)
}
