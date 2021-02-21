
require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class GitLab < OmniAuth::Strategies::OAuth2
      option :client_options, site: 'https://gitlab.com/api/v4'

      option :redirect_url

      uid { raw_info['id'].to_s }

      info do
        {
          name: raw_info['name'],
          username: raw_info['username'],
          email: raw_info['email'],
          image: raw_info['avatar_url']
        }
      end

      extra do
        { raw_info: raw_info }
      end

      def raw_info
        @raw_info ||= access_token.get('user').parsed
      end

      def build_access_token
        verifier = request.params["code"]
        # Override regular client when using setup: proc
        if env['omniauth.params']['client_id'] && env['omniauth.params']['client_secret'] && env['omniauth.params']['site']
          client = ::OAuth2::Client.new(
            env['omniauth.params']['client_id'],
            env['omniauth.params']['client_secret'],
            site: env['omniauth.params']['site'],
          )
          client.auth_code.get_token(verifier, {:redirect_uri => callback_url}.merge(token_params.to_hash(:symbolize_keys => true)), deep_symbolize(options.auth_token_params))
        else
          super
        end
      end

      private

      def callback_url
        options.redirect_url || (full_host + script_name + callback_path)
      end
    end
  end
end

OmniAuth.config.add_camelization 'gitlab', 'GitLab'
