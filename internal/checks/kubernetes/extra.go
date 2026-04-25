package kubernetes

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"github.com/complykit/complykit/internal/engine"
)

// These methods extend Checker defined in kubernetes.go

func (c *Checker) checkPrivilegeEscalation() []engine.Finding {
	pods, err := c.listPods()
	if err != nil {
		return []engine.Finding{skip("k8s_privilege_escalation", "Kubernetes Privilege Escalation", err.Error())}
	}
	var flagged []string
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, ct := range append(pod.Spec.Containers, pod.Spec.InitContainers...) {
			// AllowPrivilegeEscalation defaults to true, so flag unless explicitly false
			if ct.SecurityContext == nil ||
				ct.SecurityContext.AllowPrivilegeEscalation == nil ||
				*ct.SecurityContext.AllowPrivilegeEscalation {
				flagged = append(flagged, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, ct.Name))
			}
		}
	}
	if len(flagged) == 0 {
		return []engine.Finding{pass("k8s_privilege_escalation", "All workload containers explicitly disallow privilege escalation",
			soc2("CC6.6"), hipaa("164.312(a)(1)"), cis("5.2.5"))}
	}
	return []engine.Finding{fail(
		"k8s_privilege_escalation",
		fmt.Sprintf("%d container(s) may allow privilege escalation: %v", len(flagged), truncate(flagged, 5)),
		engine.SeverityHigh,
		"Set allowPrivilegeEscalation: false in all container securityContexts:\n  securityContext:\n    allowPrivilegeEscalation: false",
		soc2("CC6.6"), hipaa("164.312(a)(1)"), cis("5.2.5"),
	)}
}

func (c *Checker) checkCapabilityDrop() []engine.Finding {
	pods, err := c.listPods()
	if err != nil {
		return []engine.Finding{skip("k8s_capability_drop", "Kubernetes Capability Drop", err.Error())}
	}
	var flagged []string
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, ct := range append(pod.Spec.Containers, pod.Spec.InitContainers...) {
			dropsAll := false
			if ct.SecurityContext != nil && ct.SecurityContext.Capabilities != nil {
				for _, cap := range ct.SecurityContext.Capabilities.Drop {
					if cap == "ALL" {
						dropsAll = true
						break
					}
				}
			}
			if !dropsAll {
				flagged = append(flagged, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, ct.Name))
			}
		}
	}
	if len(flagged) == 0 {
		return []engine.Finding{pass("k8s_capability_drop", "All workload containers drop all Linux capabilities",
			soc2("CC6.6"), hipaa("164.312(a)(1)"), cis("5.2.7"))}
	}
	return []engine.Finding{fail(
		"k8s_capability_drop",
		fmt.Sprintf("%d container(s) do not drop all capabilities: %v", len(flagged), truncate(flagged, 5)),
		engine.SeverityMedium,
		"Drop all capabilities and add back only what is needed:\n  securityContext:\n    capabilities:\n      drop: [\"ALL\"]\n      add: [\"NET_BIND_SERVICE\"]  # only if required",
		soc2("CC6.6"), hipaa("164.312(a)(1)"), cis("5.2.7"),
	)}
}

func (c *Checker) checkHostPathMounts() []engine.Finding {
	pods, err := c.listPods()
	if err != nil {
		return []engine.Finding{skip("k8s_hostpath_mounts", "Kubernetes HostPath Mounts", err.Error())}
	}
	var flagged []string
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, vol := range pod.Spec.Volumes {
			if vol.HostPath != nil && vol.HostPath.Path != "" {
				flagged = append(flagged, fmt.Sprintf("%s/%s→%s", pod.Namespace, pod.Name, vol.HostPath.Path))
			}
		}
	}
	if len(flagged) == 0 {
		return []engine.Finding{pass("k8s_hostpath_mounts", "No pods use writable hostPath volume mounts",
			soc2("CC6.6"), hipaa("164.312(a)(1)"), cis("5.2.9"))}
	}
	return []engine.Finding{fail(
		"k8s_hostpath_mounts",
		fmt.Sprintf("%d pod(s) use hostPath volume mounts: %v", len(flagged), truncate(flagged, 5)),
		engine.SeverityHigh,
		"Replace hostPath volumes with PersistentVolumeClaims or emptyDir:\n  volumes:\n  - name: data\n    emptyDir: {}",
		soc2("CC6.6"), hipaa("164.312(a)(1)"), cis("5.2.9"),
	)}
}

func (c *Checker) checkSeccompProfiles() []engine.Finding {
	pods, err := c.listPods()
	if err != nil {
		return []engine.Finding{skip("k8s_seccomp", "Kubernetes Seccomp Profiles", err.Error())}
	}
	var noSeccomp []string
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		hasSeccomp := pod.Spec.SecurityContext != nil &&
			pod.Spec.SecurityContext.SeccompProfile != nil
		if !hasSeccomp {
			noSeccomp = append(noSeccomp, pod.Namespace+"/"+pod.Name)
		}
	}
	if len(noSeccomp) == 0 {
		return []engine.Finding{pass("k8s_seccomp", "All workload pods have a seccomp profile set",
			soc2("CC6.6"), cis("5.7.2"))}
	}
	return []engine.Finding{fail(
		"k8s_seccomp",
		fmt.Sprintf("%d pod(s) without seccomp profile: %v", len(noSeccomp), truncate(noSeccomp, 5)),
		engine.SeverityMedium,
		"Set seccomp profile on pods:\n  securityContext:\n    seccompProfile:\n      type: RuntimeDefault",
		soc2("CC6.6"), cis("5.7.2"),
	)}
}

func (c *Checker) checkWildcardRoles() []engine.Finding {
	roles, err := c.client.RbacV1().Roles("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return []engine.Finding{skip("k8s_wildcard_roles", "Kubernetes Wildcard Roles", err.Error())}
	}
	clusterRoles, err := c.client.RbacV1().ClusterRoles().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return []engine.Finding{skip("k8s_wildcard_roles", "Kubernetes Wildcard Roles", err.Error())}
	}

	var flagged []string
	for _, role := range roles.Items {
		if isSystemNamespace(role.Namespace) {
			continue
		}
		for _, rule := range role.Rules {
			if containsWildcard(rule.Verbs) || containsWildcard(rule.Resources) {
				flagged = append(flagged, fmt.Sprintf("Role/%s/%s", role.Namespace, role.Name))
				break
			}
		}
	}
	for _, cr := range clusterRoles.Items {
		if strings.HasPrefix(cr.Name, "system:") {
			continue
		}
		for _, rule := range cr.Rules {
			if containsWildcard(rule.Verbs) || containsWildcard(rule.Resources) {
				flagged = append(flagged, fmt.Sprintf("ClusterRole/%s", cr.Name))
				break
			}
		}
	}

	if len(flagged) == 0 {
		return []engine.Finding{pass("k8s_wildcard_roles", "No roles use wildcard verbs or resources",
			soc2("CC6.3"), hipaa("164.308(a)(3)"), cis("5.1.3"))}
	}
	return []engine.Finding{fail(
		"k8s_wildcard_roles",
		fmt.Sprintf("%d role(s) with wildcard (*) verbs or resources: %v", len(flagged), truncate(flagged, 5)),
		engine.SeverityHigh,
		"Replace wildcard permissions with specific verbs and resources:\n  rules:\n  - apiGroups: [\"\"]\n    resources: [\"pods\"]\n    verbs: [\"get\",\"list\",\"watch\"]",
		soc2("CC6.3"), hipaa("164.308(a)(3)"), cis("5.1.3"),
	)}
}

func (c *Checker) checkSATokenAutomount() []engine.Finding {
	sas, err := c.client.CoreV1().ServiceAccounts("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return []engine.Finding{skip("k8s_sa_token_automount", "Kubernetes SA Token Automount", err.Error())}
	}
	var flagged []string
	for _, sa := range sas.Items {
		if isSystemNamespace(sa.Namespace) || sa.Name == "default" {
			continue
		}
		// Flag if automount is nil (defaults to true) or explicitly true
		if sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
			flagged = append(flagged, sa.Namespace+"/"+sa.Name)
		}
	}
	if len(flagged) == 0 {
		return []engine.Finding{pass("k8s_sa_token_automount", "All service accounts disable token automounting",
			soc2("CC6.3"), hipaa("164.308(a)(3)"), cis("5.1.6"))}
	}
	return []engine.Finding{fail(
		"k8s_sa_token_automount",
		fmt.Sprintf("%d service account(s) auto-mount tokens: %v", len(flagged), truncate(flagged, 5)),
		engine.SeverityMedium,
		"Disable automounting on service accounts that don't need it:\n  automountServiceAccountToken: false",
		soc2("CC6.3"), hipaa("164.308(a)(3)"), cis("5.1.6"),
	)}
}

func (c *Checker) checkBindEscalateRoles() []engine.Finding {
	clusterRoles, err := c.client.RbacV1().ClusterRoles().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return []engine.Finding{skip("k8s_bind_escalate", "Kubernetes Bind/Escalate Roles", err.Error())}
	}
	dangerousVerbs := map[string]bool{"bind": true, "escalate": true, "impersonate": true}
	var flagged []string
	for _, cr := range clusterRoles.Items {
		if strings.HasPrefix(cr.Name, "system:") {
			continue
		}
		for _, rule := range cr.Rules {
			for _, v := range rule.Verbs {
				if dangerousVerbs[v] {
					flagged = append(flagged, cr.Name)
					break
				}
			}
		}
	}
	if len(flagged) == 0 {
		return []engine.Finding{pass("k8s_bind_escalate", "No roles grant bind/escalate/impersonate verbs",
			soc2("CC6.3"), hipaa("164.308(a)(3)"), cis("5.1.5"))}
	}
	return []engine.Finding{fail(
		"k8s_bind_escalate",
		fmt.Sprintf("%d role(s) grant bind/escalate/impersonate: %v", len(flagged), truncate(flagged, 5)),
		engine.SeverityCritical,
		"Remove bind, escalate, and impersonate verbs from roles — these allow privilege escalation:",
		soc2("CC6.3"), hipaa("164.308(a)(3)"), cis("5.1.5"),
	)}
}

func (c *Checker) checkDefaultDenyNetworkPolicies() []engine.Finding {
	namespaces, err := c.client.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return []engine.Finding{skip("k8s_default_deny", "Kubernetes Default Deny Network Policies", err.Error())}
	}
	var noDefaultDeny []string
	for _, ns := range namespaces.Items {
		if isSystemNamespace(ns.Name) {
			continue
		}
		policies, err := c.client.NetworkingV1().NetworkPolicies(ns.Name).List(context.Background(), metav1.ListOptions{})
		if err != nil {
			continue
		}
		hasDefaultDeny := false
		for _, pol := range policies.Items {
			// A default-deny policy has an empty podSelector and denies all traffic
			if pol.Spec.PodSelector.MatchLabels == nil &&
				(len(pol.Spec.Ingress) == 0 || len(pol.Spec.Egress) == 0) {
				hasDefaultDeny = true
				break
			}
		}
		if !hasDefaultDeny {
			noDefaultDeny = append(noDefaultDeny, ns.Name)
		}
	}
	if len(noDefaultDeny) == 0 {
		return []engine.Finding{pass("k8s_default_deny", "All workload namespaces have default-deny network policies",
			soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("5.3.1"))}
	}
	return []engine.Finding{fail(
		"k8s_default_deny",
		fmt.Sprintf("%d namespace(s) missing default-deny network policy: %v", len(noDefaultDeny), truncate(noDefaultDeny, 5)),
		engine.SeverityMedium,
		"Add default-deny policy to each namespace:\n  apiVersion: networking.k8s.io/v1\n  kind: NetworkPolicy\n  metadata:\n    name: default-deny-all\n  spec:\n    podSelector: {}\n    policyTypes: [Ingress, Egress]",
		soc2("CC6.6"), hipaa("164.312(e)(2)(i)"), cis("5.3.1"),
	)}
}

func (c *Checker) checkSecretsInEnvVars() []engine.Finding {
	pods, err := c.listPods()
	if err != nil {
		return []engine.Finding{skip("k8s_secrets_env_vars", "Kubernetes Secrets in Env Vars", err.Error())}
	}
	sensitiveKeywords := []string{"password", "passwd", "secret", "token", "key", "api_key", "apikey", "auth", "credential"}
	var flagged []string
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, ct := range append(pod.Spec.Containers, pod.Spec.InitContainers...) {
			for _, env := range ct.Env {
				// Flag env vars that look like secrets but use plain Value (not ValueFrom)
				if env.ValueFrom == nil && env.Value != "" {
					lname := strings.ToLower(env.Name)
					for _, kw := range sensitiveKeywords {
						if strings.Contains(lname, kw) {
							flagged = append(flagged, fmt.Sprintf("%s/%s/%s.%s", pod.Namespace, pod.Name, ct.Name, env.Name))
							break
						}
					}
				}
			}
		}
	}
	if len(flagged) == 0 {
		return []engine.Finding{pass("k8s_secrets_env_vars", "No plaintext secrets detected in pod environment variables",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("5.4.1"))}
	}
	return []engine.Finding{fail(
		"k8s_secrets_env_vars",
		fmt.Sprintf("%d env var(s) that look like plaintext secrets: %v", len(flagged), truncate(flagged, 5)),
		engine.SeverityHigh,
		"Use Kubernetes Secrets or external secret stores instead of plaintext env vars:\n  env:\n  - name: DB_PASSWORD\n    valueFrom:\n      secretKeyRef:\n        name: db-secret\n        key: password",
		soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"), cis("5.4.1"),
	)}
}

func (c *Checker) checkPodSecurityAdmission() []engine.Finding {
	namespaces, err := c.client.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return []engine.Finding{skip("k8s_psa", "Kubernetes Pod Security Admission", err.Error())}
	}
	var noLabel []string
	for _, ns := range namespaces.Items {
		if isSystemNamespace(ns.Name) {
			continue
		}
		labels := ns.Labels
		hasPSA := false
		for k := range labels {
			if strings.HasPrefix(k, "pod-security.kubernetes.io/") {
				hasPSA = true
				break
			}
		}
		if !hasPSA {
			noLabel = append(noLabel, ns.Name)
		}
	}
	if len(noLabel) == 0 {
		return []engine.Finding{pass("k8s_psa", "All workload namespaces have Pod Security Admission labels",
			soc2("CC6.6"), hipaa("164.312(a)(1)"), cis("5.2.1"))}
	}
	return []engine.Finding{fail(
		"k8s_psa",
		fmt.Sprintf("%d namespace(s) missing Pod Security Admission labels: %v", len(noLabel), truncate(noLabel, 5)),
		engine.SeverityHigh,
		"Apply Pod Security Admission labels:\n  kubectl label namespace NS pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/warn=restricted",
		soc2("CC6.6"), hipaa("164.312(a)(1)"), cis("5.2.1"),
	)}
}

func containsWildcard(items []string) bool {
	for _, item := range items {
		if item == "*" {
			return true
		}
	}
	return false
}

// ensureEnvHasNoSecretRef is a helper used to check pod containers
func envHasSecretRef(env corev1.EnvVar) bool {
	return env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil
}
