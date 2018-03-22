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

      uid { raw_user_info[:id] }

      info { raw_user_info }

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

      def raw_user_info
        @raw_user_info ||= get_user_info
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
          email: parsed_response['BlueSkyBroadcastUserProfile']['Email'],
          member_type: parse_additional_field_values_for(parsed_response, 'MEMBERTYPE')&.first,
          custom_fields_data: custom_fields_data(parsed_response),
          section_codes: parse_additional_field_values_for(parsed_response, 'PRODUCTCODE'),
          dues_class: parse_additional_field_values_for(parsed_response, 'DUESCLASS')&.first,
          free_cle_hours: parse_additional_field_values_for(parsed_response, 'FREECLECREDITHRS')&.first
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

      def custom_fields_data(parsed_response)
        { 'full_address' => parse_additional_field_values_for(parsed_response, 'FULLADDRESS')&.first }
      end

      def parse_additional_field_values_for(parsed_response, field_name)
        additional_field = parsed_response.dig('BlueSkyBroadcastUserProfile', 'AdditionalFields', 'Field')
        if additional_field.present?
          additional_field.map { |field| field['Value'] if field['Name'] == field_name }.compact.uniq
        end
      end

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
