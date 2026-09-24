package detect

import (
	"fmt"
	"strings"
	"sync"
	"time"

	v1 "blueveil/collector/internal/contract/v1"
	"blueveil/collector/internal/infraobs"
)

// Endpoint privilege transition (E1) - stateless
type EndpointPrivilegeChangeRule struct{}

func (EndpointPrivilegeChangeRule) ID() string      { return "endpoint-privilege-change" }
func (EndpointPrivilegeChangeRule) Version() string { return "1" }
func (EndpointPrivilegeChangeRule) Name() string    { return "Endpoint privilege transition" }
func (EndpointPrivilegeChangeRule) Description() string {
	return "Matches endpoint.activity with action privilege_transition and explicit integrity level. Not a vulnerability."
}
func (EndpointPrivilegeChangeRule) Evaluate(event *v1.TelemetryEvent) (Outcome, error) {
	if event == nil {
		return Outcome{}, errNilEvent
	}
	if event.GetEventType() != infraobs.EventTypeEndpointActivity {
		return Outcome{}, nil
	}
	obs, err := infraobs.Parse(event)
	if err != nil {
		return Outcome{}, fmt.Errorf("detect: endpoint-privilege: %w", err)
	}
	if obs.Endpoint.Action != "privilege_transition" {
		return Outcome{}, nil
	}
	if strings.TrimSpace(obs.Endpoint.IntegrityLevel) == "" {
		return Outcome{}, nil
	}
	// Severity is the triggering event's own rating (explicit source
	// basis): this fixed rule carries no policy to rate it.
	return Outcome{
		Matched: true, Severity: event.GetSeverity(),
		Title:    "Endpoint privilege transition observed",
		Detail:   fmt.Sprintf("host %q process %q privilege transition to %q", obs.Endpoint.Host, obs.Endpoint.Process, obs.Endpoint.IntegrityLevel),
		EventIDs: []string{event.GetId()}, Attrs: map[string]string{"integrity_level": obs.Endpoint.IntegrityLevel},
	}, nil
}

// Server service failure burst (S1) - stateful per host+service
type ServerServiceFailureBurstRule struct {
	threshold int
	window    time.Duration
	clock     func() time.Time
	mu        sync.Mutex
	windows   map[string]*netWindow
}

func NewServerServiceFailureBurstRule(threshold int, window time.Duration, clock func() time.Time) (*ServerServiceFailureBurstRule, error) {
	if err := checkBurstParams(threshold, window, "server-failure-burst"); err != nil {
		return nil, err
	}
	if clock == nil {
		return nil, fmt.Errorf("detect: server-failure-burst clock is nil")
	}
	return &ServerServiceFailureBurstRule{threshold: threshold, window: window, clock: clock, windows: map[string]*netWindow{}}, nil
}

// ThresholdWindow exposes the configured threshold and window for
// detection-engineering metadata (13F.4).
func (r *ServerServiceFailureBurstRule) ThresholdWindow() (int, time.Duration) {
	return r.threshold, r.window
}
func (r *ServerServiceFailureBurstRule) ID() string      { return "server-service-failure-burst" }
func (r *ServerServiceFailureBurstRule) Version() string { return "1" }
func (r *ServerServiceFailureBurstRule) Name() string    { return "Server service failure burst" }
func (r *ServerServiceFailureBurstRule) Description() string {
	return "Matches when one host/service accumulates threshold explicit failures inside window."
}
func (r *ServerServiceFailureBurstRule) Evaluate(event *v1.TelemetryEvent) (Outcome, error) {
	if event == nil {
		return Outcome{}, errNilEvent
	}
	if event.GetEventType() != infraobs.EventTypeServerActivity {
		return Outcome{}, nil
	}
	if err := checkNetClock(r.clock, "server-failure-burst"); err != nil {
		return Outcome{}, err
	}
	obs, err := infraobs.Parse(event)
	if err != nil {
		return Outcome{}, fmt.Errorf("detect: server-failure: %w", err)
	}
	if obs.Server.Result != "failure" && obs.Server.ServiceAction != "failure" {
		return Outcome{}, nil
	}
	at := obs.OccurredAt
	if at.IsZero() {
		return Outcome{}, fmt.Errorf("detect: server-failure needs occurred_at")
	}
	key := obs.Server.Hostname + "\x1f" + obs.Server.Service
	r.mu.Lock()
	defer r.mu.Unlock()
	w, ok := r.windows[key]
	if !ok {
		w = &netWindow{}
		r.windows[key] = w
	}
	if !w.observe(at, event.GetId(), event.GetSeverity(), r.window, r.threshold) {
		return Outcome{}, nil
	}
	return Outcome{
		Matched: true, Severity: w.peak(), Title: "Server service failure burst observed",
		Detail:   fmt.Sprintf("%d failures for %s/%s within %v", len(w.entries), obs.Server.Hostname, obs.Server.Service, r.window),
		EventIDs: w.ids(), Attrs: map[string]string{"threshold": fmt.Sprint(r.threshold), "window": r.window.String(), "count": fmt.Sprint(len(w.entries))},
	}, nil
}

// Container risky runtime policy (C1) - stateless explicit policy
type ContainerPolicy struct {
	Privileged  bool
	HostNetwork bool
	HostPID     bool
	// Severity rates every violation of this policy. It is required and
	// explicit: the rule invents no judgment of its own.
	Severity v1.Severity
}

type ContainerRiskyRuntimePolicyRule struct {
	policy ContainerPolicy
}

func NewContainerRiskyRuntimePolicyRule(p ContainerPolicy) (*ContainerRiskyRuntimePolicyRule, error) {
	if !p.Privileged && !p.HostNetwork && !p.HostPID {
		return nil, fmt.Errorf("detect: container policy must enable at least one flag")
	}
	if p.Severity == v1.Severity_SEVERITY_UNSPECIFIED {
		return nil, fmt.Errorf("detect: container policy explicit severity required")
	}
	if _, known := v1.Severity_name[int32(p.Severity)]; !known {
		return nil, fmt.Errorf("detect: container policy unknown severity %v", p.Severity)
	}
	return &ContainerRiskyRuntimePolicyRule{policy: p}, nil
}
func (r *ContainerRiskyRuntimePolicyRule) ID() string      { return "container-risky-runtime-policy" }
func (r *ContainerRiskyRuntimePolicyRule) Version() string { return "1" }
func (r *ContainerRiskyRuntimePolicyRule) Name() string    { return "Container runtime policy violation" }
func (r *ContainerRiskyRuntimePolicyRule) Description() string {
	return "Matches container.activity where explicitly configured risky flags are true. Not a compromise."
}
func (r *ContainerRiskyRuntimePolicyRule) Evaluate(event *v1.TelemetryEvent) (Outcome, error) {
	if event == nil {
		return Outcome{}, errNilEvent
	}
	if event.GetEventType() != infraobs.EventTypeContainerActivity {
		return Outcome{}, nil
	}
	obs, err := infraobs.Parse(event)
	if err != nil {
		return Outcome{}, fmt.Errorf("detect: container-policy: %w", err)
	}
	hit := ""
	if r.policy.Privileged && obs.Container.Privileged {
		hit = "privileged=true"
	} else if r.policy.HostNetwork && obs.Container.HostNetwork {
		hit = "host_network=true"
	} else if r.policy.HostPID && obs.Container.HostPID {
		hit = "host_pid=true"
	}
	if hit == "" {
		return Outcome{}, nil
	}
	return Outcome{
		Matched: true, Severity: r.policy.Severity,
		Title:    "Container runtime policy violation",
		Detail:   fmt.Sprintf("container %q image %q %s", obs.Container.ContainerID, obs.Container.Image, hit),
		EventIDs: []string{event.GetId()}, Attrs: map[string]string{"policy": hit},
	}, nil
}

// Cloud denied action burst (CL1) - stateful per principal+resource
type CloudDeniedActionBurstRule struct {
	threshold int
	window    time.Duration
	clock     func() time.Time
	mu        sync.Mutex
	windows   map[string]*netWindow
}

func NewCloudDeniedActionBurstRule(threshold int, window time.Duration, clock func() time.Time) (*CloudDeniedActionBurstRule, error) {
	if err := checkBurstParams(threshold, window, "cloud-denied-burst"); err != nil {
		return nil, err
	}
	if clock == nil {
		return nil, fmt.Errorf("detect: cloud-denied-burst clock is nil")
	}
	return &CloudDeniedActionBurstRule{threshold: threshold, window: window, clock: clock, windows: map[string]*netWindow{}}, nil
}

// ThresholdWindow exposes the configured threshold and window for
// detection-engineering metadata (13F.4).
func (r *CloudDeniedActionBurstRule) ThresholdWindow() (int, time.Duration) {
	return r.threshold, r.window
}
func (r *CloudDeniedActionBurstRule) ID() string      { return "cloud-denied-action-burst" }
func (r *CloudDeniedActionBurstRule) Version() string { return "1" }
func (r *CloudDeniedActionBurstRule) Name() string    { return "Cloud denied action burst" }
func (r *CloudDeniedActionBurstRule) Description() string {
	return "Matches when explicitly-denied cloud actions repeat past threshold inside window."
}
func (r *CloudDeniedActionBurstRule) Evaluate(event *v1.TelemetryEvent) (Outcome, error) {
	if event == nil {
		return Outcome{}, errNilEvent
	}
	if event.GetEventType() != infraobs.EventTypeCloudActivity {
		return Outcome{}, nil
	}
	if err := checkNetClock(r.clock, "cloud-denied-burst"); err != nil {
		return Outcome{}, err
	}
	obs, err := infraobs.Parse(event)
	if err != nil {
		return Outcome{}, fmt.Errorf("detect: cloud-denied: %w", err)
	}
	if obs.Cloud.Result != "denied" {
		return Outcome{}, nil
	}
	at := obs.OccurredAt
	if at.IsZero() {
		return Outcome{}, fmt.Errorf("detect: cloud-denied needs occurred_at")
	}
	key := obs.Cloud.Principal + "\x1f" + obs.Cloud.Resource
	if key == "\x1f" {
		key = obs.Cloud.Provider + "\x1f" + obs.Cloud.Action
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	w, ok := r.windows[key]
	if !ok {
		w = &netWindow{}
		r.windows[key] = w
	}
	if !w.observe(at, event.GetId(), event.GetSeverity(), r.window, r.threshold) {
		return Outcome{}, nil
	}
	return Outcome{
		Matched: true, Severity: w.peak(), Title: "Repeated cloud authorization denials observed",
		Detail:   fmt.Sprintf("%d denials for %q within %v", len(w.entries), key, r.window),
		EventIDs: w.ids(), Attrs: map[string]string{"threshold": fmt.Sprint(r.threshold), "window": r.window.String(), "count": fmt.Sprint(len(w.entries))},
	}, nil
}
