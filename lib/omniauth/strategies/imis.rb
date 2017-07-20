require 'omniauth-oauth2'
require 'rest_client'
require 'multi_xml'

module OmniAuth
  module Strategies
    class Imis < OmniAuth::Strategies::OAuth2
      option :name, 'imis'

      option :app_options, { app_event_id: nil }

      option :client_options, {
        user_info_url: 'http://store.atsol.org/ssobsb_Webservices/wsblueskybroadcast.asmx',
        authorize_url: 'http://store.atsol.org/ssobsb/sso.aspx'
      }

      uid { raw_info[:id] }

      info do
        {
          first_name: raw_info[:first_name],
          last_name: raw_info[:last_name],
          email: raw_info[:email]
        }
      end

      extra do
        { raw_info: raw_info }
      end

      def request_phase
        redirect authorize_url
      end

      def callback_phase
        slug = request.params['origin']
        account = Account.find_by(slug: slug)
        @app_event = account.app_events.where(id: options.app_options.app_event_id).first_or_create(activity_type: 'sso')

        self.access_token = {
          token: request.params['TOKEN'],
          token_expires: 60
        }
        self.env['omniauth.auth'] = auth_hash
        self.env['omniauth.origin'] = '/' + slug
        self.env['omniauth.app_event_id'] = @app_event.id
        call_app!
      end

      def creds
        self.access_token
      end

      def auth_hash
        hash = AuthHash.new(provider: name, uid: uid)
        hash.info = info
        hash.credentials = creds
        hash.extra = extra
        hash
      end

      def raw_info
        @raw_info ||= get_user_info
      end

      def get_user_info
        RestClient.proxy = proxy_url unless proxy_url.nil?

        request_log_text = "#{provider_name} Authentication Request:\nGET #{user_info_url}, params: { token: #{Provider::SECURITY_MASK} }"
        @app_event.logs.create(level: 'info', text: request_log_text)

        begin
          response = RestClient.get(user_info_url, params: { token: access_token[:token] })
        rescue RestClient::ExceptionWithResponse => _error
          begin
            response = RestClient.post(user_info_url, token: URI.decode(access_token[:token]))
          rescue RestClient::ExceptionWithResponse => e
            error_log_text = "#{provider_name} Authentication Response Error #{e.message} (code: #{e.response&.code}):\n#{e.response}"
            @app_event.logs.create(level: 'error', text: error_log_text)
            @app_event.fail!
            return {}
          end
        end

        response_log_text = "#{provider_name} Authentication Response (code: #{response.code}): \n#{response.body}"
        @app_event.logs.create(level: 'info', text: response_log_text)

        parsed_response = MultiXml.parse(response)

        info = {
          id: parsed_response['BlueSkyBroadcastUserProfile']['CustomerID'],
          first_name: parsed_response['BlueSkyBroadcastUserProfile']['FirstName'],
          last_name: parsed_response['BlueSkyBroadcastUserProfile']['LastName'],
          email: parsed_response['BlueSkyBroadcastUserProfile']['Email']
        }

        @app_event.update(raw_data: {
          user_info: {
            uid: info[:id],
            email: info[:email],
            first_name: info[:first_name],
            last_name: info[:last_name]
          }
        })

        info
      end

      private

      def authorize_url
        options.client_options.authorize_url
      end

      def proxy_url
        options.client_options.proxy_url
      end

      def user_info_url
        options.client_options.user_info_url + '/BlueSkyBroadcastGetUserProfile'
      end

      def provider_name
        options.name
      end
    end
  end
end
