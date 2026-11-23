package logging

import "unicode/utf8"

// Caps on audit fields a caller can choose freely (a request path as the
// target, a User-Agent): unauthenticated requests write audit lines, and a
// field as long as the request allows would multiply what each one costs.
const (
	maxAuditTargetID  = 1024
	maxAuditUserAgent = 512
)

// truncateField cuts s to at most max bytes on a UTF-8 boundary, marking
// the cut.
func truncateField(s string, max int) string {
	if len(s) <= max {
		return s
	}
	const mark = "...[truncated]"
	cut := max - len(mark)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + mark
}

// AuditContext holds optional context for audit log entries.
type AuditContext struct {
	IP        string
	UserAgent string
	SessionID string
	OldValue  any
	NewValue  any
	Reason    string
	Extra     map[string]any
}

// Audit logs a structured audit event for compliance.
func Audit(action, actorID, targetType, targetID, outcome string, ctx *AuditContext) {
	logger := &Root
	if auditRoot != nil {
		logger = auditRoot
	}
	targetID = truncateField(targetID, maxAuditTargetID)
	event := logger.Info().
		Str("component", "audit").
		Str("action", action).
		Str("actor_id", actorID).
		Str("target_type", targetType).
		Str("target_id", targetID).
		Str("outcome", outcome)

	if ctx != nil {
		if ctx.IP != "" {
			event = event.Str("ip", ctx.IP)
		}
		if ctx.UserAgent != "" {
			event = event.Str("user_agent", truncateField(ctx.UserAgent, maxAuditUserAgent))
		}
		if ctx.SessionID != "" {
			event = event.Str("session_id", ctx.SessionID)
		}
		if ctx.OldValue != nil {
			event = event.Interface("old_value", ctx.OldValue)
		}
		if ctx.NewValue != nil {
			event = event.Interface("new_value", ctx.NewValue)
		}
		if ctx.Reason != "" {
			event = event.Str("reason", ctx.Reason)
		}
		for k, v := range ctx.Extra {
			event = event.Interface(k, v)
		}
	}

	event.Msgf("%s %s:%s actor:%s %s", action, targetType, targetID, actorID, outcome)
}
