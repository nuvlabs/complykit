package kubernetes

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/complykit/complykit/internal/engine"
)

var dbImageKeywords = []string{
	"postgres", "mysql", "mariadb", "mongo", "redis",
	"elasticsearch", "cassandra", "cockroach", "couchdb",
}

func isDBImage(image string) bool {
	img := strings.ToLower(image)
	for _, kw := range dbImageKeywords {
		if strings.Contains(img, kw) {
			return true
		}
	}
	return false
}

// pvcRef is a namespace + PVC name pair.
type pvcRef struct{ ns, name string }

// findDBPVCs discovers PVCs belonging to database workloads using three signals:
//
//  1. Pods whose container images match known DB software names (bare deployments)
//  2. StatefulSets whose name or labels indicate a DB operator (CloudNativePG, Zalando,
//     Crunchy, Percona, etc.) — pods are resolved and their PVCs collected
//  3. PVCs that carry known operator labels directly
func (c *Checker) findDBPVCs() []pvcRef {
	seen := map[string]bool{}
	var refs []pvcRef

	add := func(ns, name string) {
		key := ns + "/" + name
		if !seen[key] && !isSystemNamespace(ns) {
			seen[key] = true
			refs = append(refs, pvcRef{ns, name})
		}
	}

	// ── Layer 1: pods running DB images ──────────────────────────────────────
	pods, _ := c.listPods()
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		if !podHasDBImage(pod) {
			continue
		}
		for _, vol := range pod.Spec.Volumes {
			if vol.PersistentVolumeClaim != nil {
				add(pod.Namespace, vol.PersistentVolumeClaim.ClaimName)
			}
		}
	}

	// ── Layer 2: StatefulSets with DB name or operator labels ─────────────────
	stsList, err := c.client.AppsV1().StatefulSets("").List(context.Background(), metav1.ListOptions{})
	if err == nil {
		for _, sts := range stsList.Items {
			if isSystemNamespace(sts.Namespace) {
				continue
			}
			if !isDBStatefulSet(sts.Name, sts.Labels) {
				continue
			}
			// Build label selector from matchLabels to find the StatefulSet's pods
			var parts []string
			for k, v := range sts.Spec.Selector.MatchLabels {
				parts = append(parts, k+"="+v)
			}
			if len(parts) == 0 {
				continue
			}
			podList, err := c.client.CoreV1().Pods(sts.Namespace).List(context.Background(), metav1.ListOptions{
				LabelSelector: strings.Join(parts, ","),
			})
			if err != nil {
				continue
			}
			for _, pod := range podList.Items {
				for _, vol := range pod.Spec.Volumes {
					if vol.PersistentVolumeClaim != nil {
						add(sts.Namespace, vol.PersistentVolumeClaim.ClaimName)
					}
				}
			}
		}
	}

	// ── Layer 3: PVCs with known operator labels ──────────────────────────────
	pvcList, err := c.client.CoreV1().PersistentVolumeClaims("").List(context.Background(), metav1.ListOptions{})
	if err == nil {
		for _, pvc := range pvcList.Items {
			if isSystemNamespace(pvc.Namespace) {
				continue
			}
			if isDBPVCLabels(pvc.Labels) {
				add(pvc.Namespace, pvc.Name)
			}
		}
	}

	return refs
}

func podHasDBImage(pod corev1.Pod) bool {
	for _, ct := range append(pod.Spec.Containers, pod.Spec.InitContainers...) {
		if isDBImage(ct.Image) {
			return true
		}
	}
	return false
}

// isDBStatefulSet returns true when the StatefulSet name or labels suggest it is
// managed by a database operator or is a manually deployed database.
func isDBStatefulSet(name string, lbls map[string]string) bool {
	nameLower := strings.ToLower(name)
	for _, kw := range dbImageKeywords {
		if strings.Contains(nameLower, kw) {
			return true
		}
	}
	return isDBPVCLabels(lbls)
}

// isDBPVCLabels detects operator-managed DB PVCs by their labels.
// Covers: CloudNativePG, Zalando postgres-operator, Crunchy PGO,
// Percona PXC/MongoDB, and generic app.kubernetes.io conventions.
func isDBPVCLabels(lbls map[string]string) bool {
	if len(lbls) == 0 {
		return false
	}

	// CloudNativePG
	if _, ok := lbls["cnpg.io/cluster"]; ok {
		return true
	}
	// Zalando postgres-operator
	if lbls["application"] == "spilo" {
		return true
	}
	// Crunchy Data PGO
	if _, ok := lbls["postgres-operator.crunchydata.com/cluster"]; ok {
		return true
	}
	// Percona operators (PXC, PSMDB, PS)
	if strings.Contains(strings.ToLower(lbls["app.kubernetes.io/managed-by"]), "percona") {
		return true
	}
	// Generic: component = database / db / primary / replica
	switch strings.ToLower(lbls["app.kubernetes.io/component"]) {
	case "database", "db", "primary", "replica":
		return true
	}
	// Generic: app.kubernetes.io/name or app label contains DB keyword
	for _, key := range []string{"app.kubernetes.io/name", "app"} {
		v := strings.ToLower(lbls[key])
		for _, kw := range dbImageKeywords {
			if strings.Contains(v, kw) {
				return true
			}
		}
	}
	return false
}

// checkDBPVCEncryption verifies that PVCs used by database workloads use an encrypted StorageClass.
// DB workloads are detected via three signals: image names, StatefulSet labels, and operator PVC labels.
func (c *Checker) checkDBPVCEncryption() []engine.Finding {
	dbPVCs := c.findDBPVCs()
	if len(dbPVCs) == 0 {
		return nil
	}

	var unencrypted []string
	for _, ref := range dbPVCs {
		pvc, err := c.client.CoreV1().PersistentVolumeClaims(ref.ns).Get(context.Background(), ref.name, metav1.GetOptions{})
		if err != nil {
			continue
		}
		scName := ""
		if pvc.Spec.StorageClassName != nil {
			scName = *pvc.Spec.StorageClassName
		}
		if scName == "" {
			unencrypted = append(unencrypted, fmt.Sprintf("%s/%s (no StorageClass)", ref.ns, ref.name))
			continue
		}
		sc, err := c.client.StorageV1().StorageClasses().Get(context.Background(), scName, metav1.GetOptions{})
		if err != nil {
			continue
		}
		if !storageClassEncrypted(sc.Parameters) {
			unencrypted = append(unencrypted, fmt.Sprintf("%s/%s (StorageClass: %s)", ref.ns, ref.name, scName))
		}
	}

	if len(unencrypted) == 0 {
		return []engine.Finding{pass("k8s_db_pvc_encrypted", "Database pod PVCs use encrypted StorageClass",
			soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"))}
	}
	return []engine.Finding{fail(
		"k8s_db_pvc_encrypted",
		fmt.Sprintf("%d DB PVC(s) without encrypted StorageClass: %v", len(unencrypted), truncate(unencrypted, 5)),
		engine.SeverityHigh,
		"Use a StorageClass with encryption enabled:\n  AWS EBS — set encrypted: \"true\" in StorageClass parameters\n  GCP Persistent Disk — use CMEK or default Google-managed encryption\n  Azure Managed Disk — encryption is on by default; verify your StorageClass",
		soc2("CC6.7"), hipaa("164.312(a)(2)(iv)"),
	)}
}

func storageClassEncrypted(params map[string]string) bool {
	for k, v := range params {
		kl := strings.ToLower(k)
		vl := strings.ToLower(v)
		if (kl == "encrypted" || kl == "encryption") && (vl == "true" || vl == "1") {
			return true
		}
	}
	return false
}

// checkDBNotRoot verifies that containers running database images do not run as root (uid=0).
func (c *Checker) checkDBNotRoot() []engine.Finding {
	pods, err := c.listPods()
	if err != nil {
		return []engine.Finding{skip("k8s_db_not_root", "Kubernetes DB Containers Not Root", err.Error())}
	}

	var flagged []string
	for _, pod := range pods {
		if isSystemNamespace(pod.Namespace) {
			continue
		}
		for _, ct := range append(pod.Spec.Containers, pod.Spec.InitContainers...) {
			if !isDBImage(ct.Image) {
				continue
			}
			runsAsRoot := false
			// Pod-level context
			if pod.Spec.SecurityContext != nil && pod.Spec.SecurityContext.RunAsNonRoot != nil && !*pod.Spec.SecurityContext.RunAsNonRoot {
				runsAsRoot = true
			}
			// Container-level context overrides pod-level
			if ct.SecurityContext != nil {
				if ct.SecurityContext.RunAsUser != nil && *ct.SecurityContext.RunAsUser == 0 {
					runsAsRoot = true
				}
				if ct.SecurityContext.RunAsNonRoot != nil {
					runsAsRoot = !*ct.SecurityContext.RunAsNonRoot
				}
			} else if pod.Spec.SecurityContext == nil {
				// No security context set — running as root by default
				runsAsRoot = true
			}
			if runsAsRoot {
				flagged = append(flagged, fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.Name, ct.Name))
			}
		}
	}

	if len(flagged) == 0 {
		return []engine.Finding{pass("k8s_db_not_root", "All database containers run as non-root",
			soc2("CC6.1"), hipaa("164.312(a)(1)"))}
	}
	return []engine.Finding{fail(
		"k8s_db_not_root",
		fmt.Sprintf("%d database container(s) running as root: %v", len(flagged), truncate(flagged, 5)),
		engine.SeverityHigh,
		"Set runAsNonRoot: true in the database container's securityContext:\n"+
			"  securityContext:\n    runAsNonRoot: true\n    runAsUser: 999  # or the image's default DB uid",
		soc2("CC6.1"), hipaa("164.312(a)(1)"),
	)}
}

// checkDBSecretNotConfigMap scans ConfigMaps for database credentials or connection strings.
// Credentials in ConfigMaps are unencrypted and visible to any pod in the namespace.
func (c *Checker) checkDBSecretNotConfigMap() []engine.Finding {
	cmList, err := c.client.CoreV1().ConfigMaps("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return []engine.Finding{skip("k8s_db_secret_not_configmap", "Kubernetes DB Credentials in ConfigMaps", err.Error())}
	}

	// Keys that should never appear in a ConfigMap (belong in a Secret)
	credKeys := []string{
		"database_url", "db_password", "db_pass", "db_url",
		"postgres_password", "mysql_root_password", "mysql_password",
		"mongo_initdb_root_password", "mongodb_password",
		"redis_password", "redis_url",
	}
	// Value patterns that indicate a connection string with embedded credentials
	connStringPrefixes := []string{
		"postgres://", "postgresql://", "mysql://", "mongodb://",
		"mongodb+srv://", "redis://:@", "amqp://",
	}

	var flagged []string
	for _, cm := range cmList.Items {
		if isSystemNamespace(cm.Namespace) {
			continue
		}
		for k, v := range cm.Data {
			kl := strings.ToLower(k)
			vl := strings.ToLower(v)

			// Check key name
			for _, ck := range credKeys {
				if strings.Contains(kl, ck) && v != "" {
					flagged = append(flagged, fmt.Sprintf("%s/%s (key: %s)", cm.Namespace, cm.Name, k))
					goto nextEntry
				}
			}
			// Check value for connection strings with credentials (user:pass@host pattern)
			for _, prefix := range connStringPrefixes {
				if strings.HasPrefix(vl, prefix) && strings.Contains(vl, "@") {
					flagged = append(flagged, fmt.Sprintf("%s/%s (key: %s has connection string)", cm.Namespace, cm.Name, k))
					goto nextEntry
				}
			}
		nextEntry:
		}
	}

	if len(flagged) == 0 {
		return []engine.Finding{pass("k8s_db_secret_not_configmap", "No database credentials found in ConfigMaps",
			soc2("CC6.1"), hipaa("164.312(a)(2)(iv)"))}
	}
	return []engine.Finding{fail(
		"k8s_db_secret_not_configmap",
		fmt.Sprintf("%d ConfigMap(s) contain database credentials: %v", len(flagged), truncate(flagged, 5)),
		engine.SeverityCritical,
		"Move database credentials to Kubernetes Secrets:\n"+
			"  kubectl create secret generic db-creds --from-literal=password=<value>\n"+
			"  Then reference via secretKeyRef in pod spec.\n"+
			"  For production: use External Secrets Operator or Vault Agent Injector.",
		soc2("CC6.1"), hipaa("164.312(a)(2)(iv)"),
	)}
}

// checkDBNoPublicService verifies that no Kubernetes Service exposes database ports
// via LoadBalancer or NodePort.
func (c *Checker) checkDBNoPublicService() []engine.Finding {
	services, err := c.client.CoreV1().Services("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return []engine.Finding{skip("k8s_db_no_public_service", "Kubernetes DB Services Not Public", err.Error())}
	}

	dbPorts := map[int32]string{
		5432: "PostgreSQL", 3306: "MySQL/MariaDB", 1433: "SQL Server",
		27017: "MongoDB", 6379: "Redis", 5984: "CouchDB",
	}

	var exposed []string
	for _, svc := range services.Items {
		if isSystemNamespace(svc.Namespace) {
			continue
		}
		svcType := string(svc.Spec.Type)
		if svcType != "LoadBalancer" && svcType != "NodePort" {
			continue
		}
		for _, port := range svc.Spec.Ports {
			if proto, ok := dbPorts[port.Port]; ok {
				exposed = append(exposed, fmt.Sprintf("%s/%s (%s port %d via %s)",
					svc.Namespace, svc.Name, proto, port.Port, svcType))
			}
		}
	}

	if len(exposed) == 0 {
		return []engine.Finding{pass("k8s_db_no_public_service", "No database ports exposed via LoadBalancer or NodePort",
			soc2("CC6.1"), hipaa("164.312(a)(1)"))}
	}
	return []engine.Finding{fail(
		"k8s_db_no_public_service",
		fmt.Sprintf("%d database Service(s) publicly exposed: %v", len(exposed), truncate(exposed, 5)),
		engine.SeverityCritical,
		"Change database Service type to ClusterIP. Database services must never be LoadBalancer or NodePort.\n  Use kubectl port-forward or a bastion host for admin access.",
		soc2("CC6.1"), hipaa("164.312(a)(1)"),
	)}
}
