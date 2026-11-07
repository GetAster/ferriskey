use crate::{
    ApplicationService,
    domain::{
        abyss::identity_provider::broker::{
            self, BrokerCallbackInput, BrokerCallbackOutput, BrokerLoginOutput, BrokerService,
            BrokeredUserInfo, OAuthProviderConfig, OAuthTokenResponse,
        },
        common::entities::app_errors::CoreError,
    },
};

impl BrokerService for ApplicationService {
    async fn extract_user_info(
        &self,
        config: &OAuthProviderConfig,
        token_response: &OAuthTokenResponse,
        expected_nonce: Option<&str>,
    ) -> Result<BrokeredUserInfo, CoreError> {
        self.broker_service
            .extract_user_info(config, token_response, expected_nonce)
            .await
    }

    async fn handle_callback(
        &self,
        input: BrokerCallbackInput,
    ) -> Result<BrokerCallbackOutput, CoreError> {
        use crate::domain::trident::ports::{MagicLinkInput, TridentService};
        let realm_name = input.realm_name.clone();
        let base_url = input.webapp_base_url.clone();
        let user_agent = input.user_agent.clone();
        let result = self.broker_service.handle_callback(input).await?;
        if let Some(intent) = &result.pending_provider_link {
            self.trident_service
                .generate_magic_link(MagicLinkInput {
                    realm_name,
                    email: intent.email.clone(),
                    base_url,
                    session_code: result.browser_session_id.map(|s| s.to_string()),
                    remember_me: intent.remember_me,
                    user_agent,
                    provider_link: Some(intent.clone()),
                })
                .await?;
        }
        Ok(result)
    }

    async fn initiate_login(
        &self,
        input: broker::BrokerLoginInput,
    ) -> Result<BrokerLoginOutput, CoreError> {
        self.broker_service.initiate_login(input).await
    }
}
