use url::Url;

#[derive(Debug, Clone)]
pub struct FormInput {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct Form {
    pub action: String,
    pub method: String,
    pub inputs: Vec<FormInput>,
    pub url: Url,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_form_input_creation() {
        let input = FormInput {
            name: "username".to_string(),
            value: "test_user".to_string(),
        };

        assert_eq!(input.name, "username");
        assert_eq!(input.value, "test_user");
    }

    #[test]
    fn test_form_creation() {
        let url = Url::parse("https://example.com/page").unwrap();
        let inputs = vec![
            FormInput {
                name: "email".to_string(),
                value: "".to_string(),
            },
            FormInput {
                name: "password".to_string(),
                value: "".to_string(),
            },
        ];

        let form = Form {
            action: "/submit".to_string(),
            method: "POST".to_string(),
            inputs: inputs.clone(),
            url: url.clone(),
        };

        assert_eq!(form.action, "/submit");
        assert_eq!(form.method, "POST");
        assert_eq!(form.inputs.len(), 2);
        assert_eq!(form.url, url);
    }

    #[test]
    fn test_form_empty_inputs() {
        let url = Url::parse("https://example.com").unwrap();
        let form = Form {
            action: "".to_string(),
            method: "get".to_string(),
            inputs: vec![],
            url,
        };

        assert!(form.inputs.is_empty());
        assert!(form.action.is_empty());
    }
}
