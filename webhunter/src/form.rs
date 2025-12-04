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
