package infraobs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"blueveil/collector/internal/contract"
	v1 "blueveil/collector/internal/contract/v1"
)

const (
	EventTypeEndpointActivity  = "endpoint.activity"
	EventTypeServerActivity    = "server.activity"
	EventTypeContainerActivity = "container.activity"
	EventTypeCloudActivity     = "cloud.activity"
)

var validEndpointActions = map[string]bool{
	"process_start": true, "privilege_transition": true, "file_modify": true, "process_end": true,
}

var validServerActions = map[string]bool{
	"start": true, "stop": true, "restart": true, "failure": true, "success": true,
}

var validContainerActions = map[string]bool{
	"start": true, "stop": true, "create": true, "remove": true,
}

var validCloudProviders = map[string]bool{"aws": true, "azure": true, "gcp": true}
var validCloudResults = map[string]bool{"success": true, "denied": true, "failure": true}

// Attribute redaction uses the canonical contract.SensitiveField; no
// layer keeps its own fragment list (see contract/sensitive.go).

type Observation struct {
	EventID    string
	Source     string
	AssetID    string
	OccurredAt time.Time
	Severity   v1.Severity
	Type       string
	Endpoint   EndpointObservation
	Server     ServerObservation
	Container  ContainerObservation
	Cloud      CloudObservation
	RawAttrs   map[string]string
}

type EndpointObservation struct {
	Host           string
	Process        string
	PID            int
	HasPID         bool
	ParentPID      int
	HasParentPID   bool
	Executable     string
	Command        string
	User           string
	Action         string
	FilePath       string
	Hash           string
	IntegrityLevel string
	Result         string
}

type ServerObservation struct {
	Hostname      string
	Service       string
	ServiceAction string
	Process       string
	Port          int
	HasPort       bool
	Protocol      string
	Result        string
	Resource      string
}

type ContainerObservation struct {
	Runtime     string
	ContainerID string
	Image       string
	ImageDigest string
	Namespace   string
	Pod         string
	Cluster     string
	Action      string
	Process     string
	User        string
	Privileged  bool
	HostNetwork bool
	HostPID     bool
	Result      string
}

type CloudObservation struct {
	Provider     string
	Account      string
	Region       string
	Service      string
	Resource     string
	Action       string
	Principal    string
	Result       string
	ResourceType string
	RequestID    string
}

func Parse(event *v1.TelemetryEvent) (Observation, error) {
	var o Observation
	if event == nil {
		return o, fmt.Errorf("infraobs: nil event")
	}
	switch event.GetEventType() {
	case EventTypeEndpointActivity:
		return parseEndpoint(event)
	case EventTypeServerActivity:
		return parseServer(event)
	case EventTypeContainerActivity:
		return parseContainer(event)
	case EventTypeCloudActivity:
		return parseCloud(event)
	default:
		return o, fmt.Errorf("infraobs: unknown event_type %q", event.GetEventType())
	}
}

func cleanAttrs(attrs map[string]string) map[string]string {
	clean := map[string]string{}
	for k, v := range attrs {
		low := strings.ToLower(k)
		if low == "endpoint.command" {
			clean[k] = redactCommand(v)
			continue
		}
		if contract.SensitiveField(k) {
			continue
		}
		clean[k] = v
	}
	return clean
}

func redactCommand(cmd string) string {
	// Replace --password X, --token X, --secret X patterns
	parts := strings.Fields(cmd)
	for i, p := range parts {
		low := strings.ToLower(p)
		if strings.Contains(low, "password") || strings.Contains(low, "token") || strings.Contains(low, "secret") {
			if i+1 < len(parts) {
				parts[i+1] = "***"
			} else {
				parts[i] = strings.ReplaceAll(p, low, "***")
			}
		}
		// Also handle --password=foo form
		if strings.Contains(p, "=") {
			kv := strings.SplitN(p, "=", 2)
			if len(kv) == 2 {
				lowk := strings.ToLower(kv[0])
				if strings.Contains(lowk, "password") || strings.Contains(lowk, "token") || strings.Contains(lowk, "secret") {
					parts[i] = kv[0] + "=***"
				}
			}
		}
	}
	// Also redact bare secret tokens like "secret123"
	for i, p := range parts {
		if strings.Contains(strings.ToLower(p), "secret") {
			parts[i] = "***"
		}
	}
	return strings.Join(parts, " ")
}

func parseEndpoint(event *v1.TelemetryEvent) (Observation, error) {
	var o Observation
	attrs := cleanAttrs(event.GetAttributes())
	host := strings.TrimSpace(attrs["endpoint.host"])
	if host == "" {
		return o, fmt.Errorf("infraobs: endpoint.host required")
	}
	proc := strings.TrimSpace(attrs["endpoint.process"])
	if proc == "" {
		return o, fmt.Errorf("infraobs: endpoint.process required")
	}
	action := strings.ToLower(strings.TrimSpace(attrs["endpoint.action"]))
	if action == "" {
		action = "process_start"
	}
	if !validEndpointActions[action] {
		return o, fmt.Errorf("infraobs: unknown endpoint.action %q", action)
	}
	pid := 0
	hasPID := false
	if s := strings.TrimSpace(attrs["endpoint.pid"]); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return o, fmt.Errorf("infraobs: invalid endpoint.pid %q", s)
		}
		pid = n
		hasPID = true
	}
	ppid := 0
	hasPPID := false
	if s := strings.TrimSpace(attrs["endpoint.parent_pid"]); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return o, fmt.Errorf("infraobs: invalid endpoint.parent_pid %q", s)
		}
		ppid = n
		hasPPID = true
	}
	cmd := strings.TrimSpace(attrs["endpoint.command"])
	// Already redacted via cleanAttrs but ensure
	if strings.Contains(strings.ToLower(attrs["endpoint.command"]), "secret") {
		cmd = redactCommand(attrs["endpoint.command"])
	}
	o = Observation{
		EventID: event.GetId(), Source: event.GetSource(), AssetID: event.GetAssetId(),
		OccurredAt: event.GetOccurredAt().AsTime(), Severity: event.GetSeverity(), Type: EventTypeEndpointActivity,
		Endpoint: EndpointObservation{
			Host: host, Process: proc, PID: pid, HasPID: hasPID, ParentPID: ppid, HasParentPID: hasPPID,
			Executable: strings.TrimSpace(attrs["endpoint.executable"]), Command: cmd,
			User: strings.TrimSpace(attrs["endpoint.user"]), Action: action,
			FilePath: strings.TrimSpace(attrs["endpoint.file_path"]), Hash: strings.ToLower(strings.TrimSpace(attrs["endpoint.hash"])),
			IntegrityLevel: strings.ToLower(strings.TrimSpace(attrs["endpoint.integrity_level"])),
			Result:         strings.ToLower(strings.TrimSpace(attrs["endpoint.result"])),
		},
		RawAttrs: attrs,
	}
	return o, nil
}

func parseServer(event *v1.TelemetryEvent) (Observation, error) {
	var o Observation
	attrs := cleanAttrs(event.GetAttributes())
	hostname := strings.TrimSpace(attrs["server.hostname"])
	if hostname == "" {
		return o, fmt.Errorf("infraobs: server.hostname required")
	}
	service := strings.TrimSpace(attrs["server.service"])
	if service == "" {
		return o, fmt.Errorf("infraobs: server.service required")
	}
	action := strings.ToLower(strings.TrimSpace(attrs["server.service_action"]))
	if action == "" {
		action = strings.ToLower(strings.TrimSpace(attrs["server.action"]))
	}
	if action != "" && !validServerActions[action] && action != "failure" && action != "success" {
		// Allow failure/success
		return o, fmt.Errorf("infraobs: unknown server action %q", action)
	}
	port := 0
	hasPort := false
	if s := strings.TrimSpace(attrs["server.port"]); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 65535 {
			return o, fmt.Errorf("infraobs: invalid server.port %q", s)
		}
		port = n
		hasPort = true
	}
	o = Observation{
		EventID: event.GetId(), Source: event.GetSource(), AssetID: event.GetAssetId(),
		OccurredAt: event.GetOccurredAt().AsTime(), Severity: event.GetSeverity(), Type: EventTypeServerActivity,
		Server: ServerObservation{
			Hostname: hostname, Service: service, ServiceAction: action,
			Process: strings.TrimSpace(attrs["server.process"]), Port: port, HasPort: hasPort,
			Protocol: strings.ToLower(strings.TrimSpace(attrs["server.protocol"])),
			Result:   strings.ToLower(strings.TrimSpace(attrs["server.result"])),
			Resource: strings.TrimSpace(attrs["server.resource"]),
		},
		RawAttrs: attrs,
	}
	return o, nil
}

func parseContainer(event *v1.TelemetryEvent) (Observation, error) {
	var o Observation
	attrs := cleanAttrs(event.GetAttributes())
	cid := strings.TrimSpace(attrs["container.container_id"])
	if cid == "" {
		return o, fmt.Errorf("infraobs: container.container_id required")
	}
	image := strings.TrimSpace(attrs["container.image"])
	if image == "" {
		return o, fmt.Errorf("infraobs: container.image required")
	}
	action := strings.ToLower(strings.TrimSpace(attrs["container.action"]))
	if action != "" && !validContainerActions[action] {
		return o, fmt.Errorf("infraobs: unknown container.action %q", action)
	}
	priv := strings.ToLower(strings.TrimSpace(attrs["container.privileged"])) == "true"
	hnet := strings.ToLower(strings.TrimSpace(attrs["container.host_network"])) == "true"
	hpid := strings.ToLower(strings.TrimSpace(attrs["container.host_pid"])) == "true"
	o = Observation{
		EventID: event.GetId(), Source: event.GetSource(), AssetID: event.GetAssetId(),
		OccurredAt: event.GetOccurredAt().AsTime(), Severity: event.GetSeverity(), Type: EventTypeContainerActivity,
		Container: ContainerObservation{
			Runtime: strings.TrimSpace(attrs["container.runtime"]), ContainerID: cid, Image: image,
			ImageDigest: strings.TrimSpace(attrs["container.image_digest"]), Namespace: strings.TrimSpace(attrs["container.namespace"]),
			Pod: strings.TrimSpace(attrs["container.pod"]), Cluster: strings.TrimSpace(attrs["container.cluster"]),
			Action: action, Process: strings.TrimSpace(attrs["container.process"]), User: strings.TrimSpace(attrs["container.user"]),
			Privileged: priv, HostNetwork: hnet, HostPID: hpid,
			Result: strings.ToLower(strings.TrimSpace(attrs["container.result"])),
		},
		RawAttrs: attrs,
	}
	return o, nil
}

func parseCloud(event *v1.TelemetryEvent) (Observation, error) {
	var o Observation
	attrs := cleanAttrs(event.GetAttributes())
	provider := strings.ToLower(strings.TrimSpace(attrs["cloud.provider"]))
	if provider == "" || !validCloudProviders[provider] {
		return o, fmt.Errorf("infraobs: invalid cloud.provider %q", provider)
	}
	action := strings.TrimSpace(attrs["cloud.action"])
	if action == "" {
		return o, fmt.Errorf("infraobs: cloud.action required")
	}
	result := strings.ToLower(strings.TrimSpace(attrs["cloud.result"]))
	if result == "" {
		result = "success"
	}
	if !validCloudResults[result] {
		return o, fmt.Errorf("infraobs: unknown cloud.result %q", result)
	}
	o = Observation{
		EventID: event.GetId(), Source: event.GetSource(), AssetID: event.GetAssetId(),
		OccurredAt: event.GetOccurredAt().AsTime(), Severity: event.GetSeverity(), Type: EventTypeCloudActivity,
		Cloud: CloudObservation{
			Provider: provider, Account: strings.TrimSpace(attrs["cloud.account"]), Region: strings.TrimSpace(attrs["cloud.region"]),
			Service: strings.TrimSpace(attrs["cloud.service"]), Resource: strings.TrimSpace(attrs["cloud.resource"]),
			Action: action, Principal: strings.TrimSpace(attrs["cloud.principal"]), Result: result,
			ResourceType: strings.TrimSpace(attrs["cloud.resource_type"]), RequestID: strings.TrimSpace(attrs["cloud.request_id"]),
		},
		RawAttrs: attrs,
	}
	return o, nil
}

func (o Observation) ID() string {
	var b strings.Builder
	b.WriteString(o.Type)
	b.WriteString("\x1f")
	switch o.Type {
	case EventTypeEndpointActivity:
		b.WriteString(o.Endpoint.Host)
		b.WriteString("\x1f")
		b.WriteString(o.Endpoint.Process)
		b.WriteString("\x1f")
		b.WriteString(o.Endpoint.Action)
	case EventTypeServerActivity:
		b.WriteString(o.Server.Hostname)
		b.WriteString("\x1f")
		b.WriteString(o.Server.Service)
		b.WriteString("\x1f")
		b.WriteString(o.Server.ServiceAction)
	case EventTypeContainerActivity:
		b.WriteString(o.Container.ContainerID)
		b.WriteString("\x1f")
		b.WriteString(o.Container.Image)
	case EventTypeCloudActivity:
		b.WriteString(o.Cloud.Provider)
		b.WriteString("\x1f")
		b.WriteString(o.Cloud.Action)
		b.WriteString("\x1f")
		b.WriteString(o.Cloud.Principal)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "infraobs-" + hex.EncodeToString(sum[:])[:16]
}
