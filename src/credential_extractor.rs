use anyhow::Context;
use regex::Regex;
use rust_bert::marian::{
    MarianConfigResources, MarianModelResources, MarianSourceLanguages, MarianSpmResources,
    MarianTargetLanguages, MarianVocabResources,
};
use rust_bert::pipelines::common::{ModelResource, ModelType};
use rust_bert::pipelines::question_answering::{QaInput, QuestionAnsweringModel};
use rust_bert::pipelines::translation::{TranslationConfig, TranslationModel};
use rust_bert::resources::RemoteResource;

struct MLConfig {
    trans_model: TranslationModel,
    qa_model: QuestionAnsweringModel,
}

pub struct CredentialExtractor {
    ml_conf: Option<MLConfig>,
    regexes: Vec<Regex>,
}

impl CredentialExtractor {
    pub fn new(use_ml: bool) -> anyhow::Result<Self> {
        let ml_conf: Option<MLConfig> = if use_ml {
            let model_resource =
                RemoteResource::from_pretrained(MarianModelResources::GERMAN2ENGLISH);
            let config_resource =
                RemoteResource::from_pretrained(MarianConfigResources::GERMAN2ENGLISH);
            let vocab_resource =
                RemoteResource::from_pretrained(MarianVocabResources::GERMAN2ENGLISH);
            let merges_resource =
                RemoteResource::from_pretrained(MarianSpmResources::GERMAN2ENGLISH);

            let source_languages = MarianSourceLanguages::GERMAN2ENGLISH;
            let target_languages = MarianTargetLanguages::GERMAN2ENGLISH;

            let translation_config = TranslationConfig::new(
                ModelType::Marian,
                ModelResource::Torch(Box::new(model_resource)),
                config_resource,
                vocab_resource,
                Some(merges_resource),
                source_languages,
                target_languages,
                None,
            );
            let trans_model = TranslationModel::new(translation_config)?;

            let qa_model = match QuestionAnsweringModel::new(Default::default()) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("{:?}", e);
                    return Err(e.into());
                }
            };

            Some(MLConfig {
                trans_model,
                qa_model,
            })
        } else {
            None
        };

        let regex_list = &["\"([^\"]+)\"", "'([^']+)'", "(\\S*)\\."];

        let regexes = regex_list
            .iter()
            .map(|r| Regex::new(r).context("Could not compile regex").unwrap())
            .collect();

        Ok(Self { ml_conf, regexes })
    }

    pub fn get_creds(&self, text: &str) -> anyhow::Result<Vec<String>> {
        let mut creds: Vec<String> = text.split_whitespace().map(|s| s.to_string()).collect();

        for regex in self.regexes.as_slice() {
            for m in regex.captures_iter(text) {
                creds.push(m[1].to_string());
            }
        }

        if let Some(ml) = &self.ml_conf {
            let mut context = ml.trans_model.translate(&[text], None, None)?;

            let context = context.pop().unwrap();
            let qa_input = QaInput {
                question: String::from("What is the password of the following text?"),
                context,
            };

            let mut answer = ml.qa_model.predict(&[qa_input], 1, 32);

            if !answer.is_empty() && !answer[0].is_empty() {
                let answer = answer.pop().unwrap().pop().unwrap();
                creds.push(answer.answer);
            }
        }

        Ok(creds)
    }
}
