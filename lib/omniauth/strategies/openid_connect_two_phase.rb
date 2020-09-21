require "timeout"
require "omniauth"
require "openid_connect"

module OmniAuth
  module Strategies
    class OpenIDConnectTwoPhase
      include OmniAuth::Strategy

      option :client_options, {
        identifier: nil,
        secret: nil,
        redirect_uri: nil,
        scheme: "https",
        host: nil,
        port: 443,
        authorization_endpoint: "/authorize",
        token_endpoint: "/token"
      }
      option :issuer
      option :jwks_url
      option :scope, [:openid]
      option :response_type, "code"
      option :display, nil #, [:page, :popup, :touch, :wap]
      option :prompt, nil #, [:none, :login, :consent, :select_account]
      option :client_auth_method

      uid { user_info_hash.sub }

      info do
        custom_attributes = user_info_hash.raw_attributes.fetch("lms", {})

        {
          name: user_info_hash.name,
          email: user_info_hash.email,
          nickname: user_info_hash.preferred_username,
          first_name: user_info_hash.given_name,
          last_name: user_info_hash.family_name,
          gender: user_info_hash.gender,
          image: user_info_hash.picture,
          phone: user_info_hash.phone_number,
          urls: { website: user_info_hash.website },
          groups: custom_attributes["groups"]
        }
      end

      credentials do
        {
          id_token: access_token.id_token,
          token: access_token.access_token,
          refresh_token: access_token.refresh_token,
          expires_in: access_token.expires_in,
          scope: access_token.scope
        }
      end

      extra do
        {
          raw_info: user_info_hash.raw_attributes,
          iss: user_info_hash.raw_attributes["iss"]
        }
      end

      def client
        @client ||= ::OpenIDConnect::Client.new(options.client_options)
      end

      def request_phase
        redirect authorize_uri
      end

      def callback_phase
        error = request.params["error_reason"] || request.params["error"]
        if error
          raise CallbackError.new(request.params["error"], request.params["error_description"] || request.params["error_reason"], request.params["error_uri"])
        elsif request.params["state"].to_s.empty? || request.params["state"] != stored_state
          return Rack::Response.new(["401 Unauthorized"], 401).finish
        elsif !request.params["code"]
          return fail!(:missing_code, OmniAuth::OpenIDConnectTwoPhase::MissingCodeError.new(request.params["error"]))
        else
          client.redirect_uri = options.client_options.redirect_uri
          client.authorization_code = request.params["code"]
          perform_token_request
          super
        end
      rescue CallbackError => e
        fail!(:invalid_credentials, e)
      rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
        fail!(:timeout, e)
      rescue ::SocketError => e
        fail!(:failed_to_connect, e)
      end

      def authorize_uri
        client.redirect_uri = options.client_options.redirect_uri
        client.authorization_uri(
          response_type: options.response_type,
          scope: options.scope,
          state: new_state,
          nonce: new_nonce,
          prompt: options.prompt
        )
      end

      private

      attr_reader :access_token, :user_info_hash

      def perform_token_request
        @access_token = client.access_token!(
          client_auth_method: options.client_auth_method
        )
        decoded_id_token = decode_id_token(@access_token.id_token)
        decoded_id_token.verify!(
          issuer: options.issuer,
          client_id: options.client_options.identifier,
          nonce: stored_nonce
        )

        @user_info_hash = ::OpenIDConnect::ResponseObject::UserInfo.new(
          decoded_id_token.raw_attributes
        )
      end

      def decode_id_token(id_token)
        ::OpenIDConnect::ResponseObject::IdToken.decode(id_token, key_or_secret)
      end

      def new_state
        session["omniauth.state"] = SecureRandom.hex(32)
      end

      def stored_state
        session.delete("omniauth.state")
      end

      def new_nonce
        session["omniauth.nonce"] = SecureRandom.hex(16)
      end

      def stored_nonce
        session.delete("omniauth.nonce")
      end

      def session
        @env.nil? ? {} : super
      end

      def key_or_secret
        if options.jwks_url && !options.jwks_url.empty?
          jwks = JSON.parse(
            OpenIDConnect.http_client.get_content(options.jwks_url)
          )

          if jwks["keys"].size == 1
            JSON::JWK.new(jwks["keys"].first)
          else
            JSON::JWK::Set.new(jwks["keys"])
          end
        else
          options.client_options.secret
        end
      end

      class CallbackError < StandardError
        attr_accessor :error, :error_reason, :error_uri

        def initialize(error, error_reason=nil, error_uri=nil)
          self.error = error
          self.error_reason = error_reason
          self.error_uri = error_uri
        end

        def message
          [error, error_reason, error_uri].compact.join(" | ")
        end
      end
    end
  end
end

OmniAuth.config.add_camelization "openid_connect_two_phase", "OpenIDConnectTwoPhase"
