use rust_bert::marian::{
    MarianConfigResources, MarianModelResources, MarianSourceLanguages, MarianSpmResources,
    MarianTargetLanguages, MarianVocabResources,
};
use rust_bert::pipelines::common::{ModelResource, ModelType};
use rust_bert::pipelines::question_answering::{QaInput, QuestionAnsweringModel};
use rust_bert::pipelines::translation::{TranslationConfig, TranslationModel};
use rust_bert::resources::RemoteResource;

pub struct CredentialExtractor {
    trans_model: TranslationModel,
    qa_model: QuestionAnsweringModel,
}

impl CredentialExtractor {
    pub fn new() -> anyhow::Result<Self> {
        let model_resource = RemoteResource::from_pretrained(MarianModelResources::GERMAN2ENGLISH);
        let config_resource =
            RemoteResource::from_pretrained(MarianConfigResources::GERMAN2ENGLISH);
        let vocab_resource = RemoteResource::from_pretrained(MarianVocabResources::GERMAN2ENGLISH);
        let merges_resource = RemoteResource::from_pretrained(MarianSpmResources::GERMAN2ENGLISH);

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

        Ok(Self {
            trans_model,
            qa_model,
        })
    }

    pub fn get_creds(&self, text: String) -> anyhow::Result<Option<String>> {
        let mut context = self.trans_model.translate(&[text], None, None)?;

        let context = context.pop().unwrap();
        let qa_input = QaInput {
            question: String::from("What is the password of the following text?"),
            context,
        };

        let mut answer = self.qa_model.predict(&[qa_input], 1, 32);

        if !answer.is_empty() && !answer[0].is_empty() {
            let answer = answer.pop().unwrap().pop().unwrap();
            Ok(Some(answer.answer))
        } else {
            Ok(None)
        }
    }
}
