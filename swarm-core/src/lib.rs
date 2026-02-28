pub mod models;

pub use models::{
    Backend, RestoreMode, RouteMode, RunOutcome, RunSpec, RunStatus, SchemaValidationResult,
};

pub fn validate_schema_kind(schema: &str) -> SchemaValidationResult {
    let known = ["node", "certificate", "result", "next_tokens"];
    if known.contains(&schema) {
        SchemaValidationResult {
            schema: schema.to_string(),
            valid: true,
            errors: vec![],
        }
    } else {
        SchemaValidationResult {
            schema: schema.to_string(),
            valid: false,
            errors: vec![format!(
                "unknown schema '{schema}', expected one of: {}",
                known.join(", ")
            )],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::validate_schema_kind;

    #[test]
    fn validates_known_schema() {
        let res = validate_schema_kind("certificate");
        assert!(res.valid);
        assert!(res.errors.is_empty());
    }

    #[test]
    fn rejects_unknown_schema() {
        let res = validate_schema_kind("banana");
        assert!(!res.valid);
        assert_eq!(res.errors.len(), 1);
    }
}
