package logging

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
	event := Root.Info().
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
			event = event.Str("user_agent", ctx.UserAgent)
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
