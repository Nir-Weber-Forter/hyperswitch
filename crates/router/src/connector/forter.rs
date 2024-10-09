pub mod transformers;

#[cfg(feature = "frm")]
use base64::Engine;
#[cfg(feature = "frm")]
use common_utils::{crypto, ext_traits::ByteSliceExt, request::RequestContent};
#[cfg(feature = "frm")]
use error_stack::ResultExt;
#[cfg(feature = "frm")]
use masking::{Secret};
#[cfg(feature = "frm")]
use ring::hmac;
use common_utils::types::{AmountConvertor, FloatMajorUnit, FloatMajorUnitForConnector};
#[cfg(feature = "frm")]
use transformers as forter;

#[cfg(feature = "frm")]
use crate::{
    configs::settings,
    core::errors::{self, CustomResult},
    headers,
    services::{self, request, ConnectorIntegration, ConnectorValidation},
    types::{
        self,
        api::{self, ConnectorCommon, ConnectorCommonExt},
    },
};
#[cfg(feature = "frm")]
use crate::{
    consts,
    events::connector_api_logs::ConnectorEvent,
    types::{api::fraud_check as frm_api, fraud_check as frm_types, ErrorResponse, Response},
    utils::BytesExt,
};

#[derive(Debug, Clone)]
pub struct Forter;

impl<Flow, Request, Response> ConnectorCommonExt<Flow, Request, Response> for Forter
where
    Self: ConnectorIntegration<Flow, Request, Response>,
{
    fn build_headers(
        &self,
        req: &types::RouterData<Flow, Request, Response>,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Vec<(String, request::Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            self.get_content_type().to_string().into(),
        )];

        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }
}

impl api::Payment for Forter {}
impl ConnectorCommon for Forter {
    fn id(&self) -> &'static str {
        "forter"
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }
    fn base_url<'a>(&self, connectors: &'a settings::Connectors) -> &'a str {
        connectors.forter.base_url.as_ref()
    }

    #[cfg(feature = "frm")]
    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: forter::ErrorResponse = res
            .response
            .parse_struct("ErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_error_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            attempt_status: None,
            code: consts::NO_ERROR_CODE.to_string(),
            message: response.message.clone(),
            reason: None,
            connector_transaction_id: None,
        })
    }
}
impl ConnectorValidation for Forter {}
impl api::PaymentAuthorize for Forter {}
impl api::PaymentSync for Forter {}
impl api::PaymentVoid for Forter {}
impl api::PaymentCapture for Forter {}
impl api::MandateSetup for Forter {}
impl api::ConnectorAccessToken for Forter {}
impl api::PaymentToken for Forter {}
impl api::Refund for Forter {}
impl api::RefundExecute for Forter {}
impl api::RefundSync for Forter {}

impl api::PaymentSession for Forter {}

#[cfg(feature = "frm")]
impl api::FraudCheck for Forter {}
#[cfg(feature = "frm")]
impl frm_api::FraudCheckSale for Forter {}
#[cfg(feature = "frm")]
impl frm_api::FraudCheckCheckout for Forter {}
#[cfg(feature = "frm")]
impl frm_api::FraudCheckTransaction for Forter {}
#[cfg(feature = "frm")]
impl frm_api::FraudCheckFulfillment for Forter {}
#[cfg(feature = "frm")]
impl frm_api::FraudCheckRecordReturn for Forter {}

impl ConnectorIntegration<api::Session, types::PaymentsSessionData, types::PaymentsResponseData>
for Forter
{}

impl ConnectorIntegration<api::Authorize, types::PaymentsAuthorizeData, types::PaymentsResponseData>
for Forter
{}

impl ConnectorIntegration<api::PSync, types::PaymentsSyncData, types::PaymentsResponseData>
for Forter
{}

impl ConnectorIntegration<api::Void, types::PaymentsCancelData, types::PaymentsResponseData>
for Forter
{}

impl ConnectorIntegration<api::Capture, types::PaymentsCaptureData, types::PaymentsResponseData>
for Forter
{}

impl
ConnectorIntegration<
    api::SetupMandate,
    types::SetupMandateRequestData,
    types::PaymentsResponseData,
> for Forter
{
    fn build_request(
        &self,
        _req: &types::RouterData<
            api::SetupMandate,
            types::SetupMandateRequestData,
            types::PaymentsResponseData,
        >,
        _connectors: &settings::Connectors,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        Err(
            errors::ConnectorError::NotImplemented("Setup Mandate flow for Forter".to_string())
                .into(),
        )
    }
}

impl ConnectorIntegration<api::AccessTokenAuth, types::AccessTokenRequestData, types::AccessToken>
for Forter
{}

impl
ConnectorIntegration<
    api::PaymentMethodToken,
    types::PaymentMethodTokenizationData,
    types::PaymentsResponseData,
> for Forter
{}

impl ConnectorIntegration<api::Execute, types::RefundsData, types::RefundsResponseData> for Forter {}

impl ConnectorIntegration<api::RSync, types::RefundsData, types::RefundsResponseData> for Forter {}

#[cfg(feature = "frm")]
impl
ConnectorIntegration<
    frm_api::Sale,
    frm_types::FraudCheckSaleData,
    frm_types::FraudCheckResponseData,
> for Forter
{
    fn get_headers(
        &self,
        req: &frm_types::FrmSaleRouterData,
        connectors: &settings::Connectors,
    ) -> CustomResult<Vec<(String, request::Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &frm_types::FrmSaleRouterData,
        connectors: &settings::Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        todo!()
    }

    fn get_request_body(
        &self,
        req: &frm_types::FrmSaleRouterData,
        _connectors: &settings::Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        todo!()
    }

    fn build_request(
        &self,
        req: &frm_types::FrmSaleRouterData,
        connectors: &settings::Connectors,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        todo!()
    }

    fn handle_response(
        &self,
        data: &frm_types::FrmSaleRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<frm_types::FrmSaleRouterData, errors::ConnectorError> {
        todo!()
    }
    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

#[cfg(feature = "frm")]
impl
ConnectorIntegration<
    frm_api::Checkout,
    frm_types::FraudCheckCheckoutData,
    frm_types::FraudCheckResponseData,
> for Forter
{
    fn get_headers(
        &self,
        req: &frm_types::FrmCheckoutRouterData,
        connectors: &settings::Connectors,
    ) -> CustomResult<Vec<(String, request::Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &frm_types::FrmCheckoutRouterData,
        connectors: &settings::Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        todo!()
    }

    fn get_request_body(
        &self,
        req: &frm_types::FrmCheckoutRouterData,
        _connectors: &settings::Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        todo!()
    }

    fn build_request(
        &self,
        req: &frm_types::FrmCheckoutRouterData,
        connectors: &settings::Connectors,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        todo!()
    }

    fn handle_response(
        &self,
        data: &frm_types::FrmCheckoutRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<frm_types::FrmCheckoutRouterData, errors::ConnectorError> {
        todo!()
    }
    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

#[cfg(feature = "frm")]
impl
ConnectorIntegration<
    frm_api::Transaction,
    frm_types::FraudCheckTransactionData,
    frm_types::FraudCheckResponseData,
> for Forter
{
    fn get_headers(
        &self,
        req: &frm_types::FrmTransactionRouterData,
        connectors: &settings::Connectors,
    ) -> CustomResult<Vec<(String, request::Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &frm_types::FrmTransactionRouterData,
        connectors: &settings::Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        todo!()
    }

    fn get_request_body(
        &self,
        req: &frm_types::FrmTransactionRouterData,
        _connectors: &settings::Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        todo!()
    }

    fn build_request(
        &self,
        req: &frm_types::FrmTransactionRouterData,
        connectors: &settings::Connectors,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        todo!()
    }

    fn handle_response(
        &self,
        data: &frm_types::FrmTransactionRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<frm_types::FrmTransactionRouterData, errors::ConnectorError> {
        todo!()
    }
    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

#[cfg(feature = "frm")]
impl
ConnectorIntegration<
    frm_api::Fulfillment,
    frm_types::FraudCheckFulfillmentData,
    frm_types::FraudCheckResponseData,
> for Forter
{
    fn get_headers(
        &self,
        req: &frm_types::FrmFulfillmentRouterData,
        connectors: &settings::Connectors,
    ) -> CustomResult<Vec<(String, request::Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &frm_types::FrmFulfillmentRouterData,
        connectors: &settings::Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        todo!()
    }

    fn get_request_body(
        &self,
        req: &frm_types::FrmFulfillmentRouterData,
        _connectors: &settings::Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        todo!()
    }

    fn build_request(
        &self,
        req: &frm_types::FrmFulfillmentRouterData,
        connectors: &settings::Connectors,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        todo!()
    }

    fn handle_response(
        &self,
        data: &frm_types::FrmFulfillmentRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<frm_types::FrmFulfillmentRouterData, errors::ConnectorError> {
        todo!()
    }
    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

#[cfg(feature = "frm")]
impl
ConnectorIntegration<
    frm_api::RecordReturn,
    frm_types::FraudCheckRecordReturnData,
    frm_types::FraudCheckResponseData,
> for Forter
{
    fn get_headers(
        &self,
        req: &frm_types::FrmRecordReturnRouterData,
        connectors: &settings::Connectors,
    ) -> CustomResult<Vec<(String, request::Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &frm_types::FrmRecordReturnRouterData,
        connectors: &settings::Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        todo!()
    }

    fn get_request_body(
        &self,
        req: &frm_types::FrmRecordReturnRouterData,
        _connectors: &settings::Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        todo!()
    }

    fn build_request(
        &self,
        req: &frm_types::FrmRecordReturnRouterData,
        connectors: &settings::Connectors,
    ) -> CustomResult<Option<services::Request>, errors::ConnectorError> {
        todo!()
    }

    fn handle_response(
        &self,
        data: &frm_types::FrmRecordReturnRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<frm_types::FrmRecordReturnRouterData, errors::ConnectorError> {
        todo!()
    }
    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

#[cfg(feature = "frm")]
#[async_trait::async_trait]
impl api::IncomingWebhook for Forter{
    fn get_webhook_source_verification_algorithm(
        &self,
        _request: &api::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn crypto::VerifySignature + Send>, errors::ConnectorError> {
        Ok(Box::new(crypto::HmacSha256))
    }

    fn get_webhook_source_verification_signature(
        &self,
        request: &api::IncomingWebhookRequestDetails<'_>,
        _connector_webhook_secrets: &api_models::webhooks::ConnectorWebhookSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        todo!();
    }

    fn get_webhook_source_verification_message(
        &self,
        request: &api::IncomingWebhookRequestDetails<'_>,
        _merchant_id: &common_utils::id_type::MerchantId,
        _connector_webhook_secrets: &api_models::webhooks::ConnectorWebhookSecrets,
    ) -> CustomResult<Vec<u8>, errors::ConnectorError> {
        Ok(request.body.to_vec())
    }

    async fn verify_webhook_source(
        &self,
        request: &api::IncomingWebhookRequestDetails<'_>,
        merchant_id: &common_utils::id_type::MerchantId,
        connector_webhook_details: Option<common_utils::pii::SecretSerdeValue>,
        _connector_account_details: crypto::Encryptable<Secret<serde_json::Value>>,
        connector_label: &str,
    ) -> CustomResult<bool, errors::ConnectorError> {
        let connector_webhook_secrets = self
            .get_webhook_source_verification_merchant_secret(
                merchant_id,
                connector_label,
                connector_webhook_details,
            )
            .await
            .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)?;

        let signature = self
            .get_webhook_source_verification_signature(request, &connector_webhook_secrets)
            .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)?;

        let message = self
            .get_webhook_source_verification_message(
                request,
                merchant_id,
                &connector_webhook_secrets,
            )
            .change_context(errors::ConnectorError::WebhookSourceVerificationFailed)?;

        let signing_key = hmac::Key::new(hmac::HMAC_SHA256, &connector_webhook_secrets.secret);
        let signed_message = hmac::sign(&signing_key, &message);
        let payload_sign = consts::BASE64_ENGINE.encode(signed_message.as_ref());
        Ok(payload_sign.as_bytes().eq(&signature))
    }

    fn get_webhook_object_reference_id(
        &self,
        request: &api::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api_models::webhooks::ObjectReferenceId, errors::ConnectorError> {
        todo!();
    }

    fn get_webhook_event_type(
        &self,
        request: &api::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api::IncomingWebhookEvent, errors::ConnectorError> {
        todo!();
    }

    fn get_webhook_resource_object(
        &self,
        request: &api::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn masking::ErasedMaskSerialize>, errors::ConnectorError> {
        todo!()
    }
}