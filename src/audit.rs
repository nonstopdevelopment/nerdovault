#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub ts: String,
    pub event: String,
    pub project: Option<String>,
    pub key_name: Option<String>,
    pub detail: Option<String>,
}
