
require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class GitLab < OmniAuth::Strategies::OAuth2

      args %i[client_id client_secret]

      option :client_options, {
        site: "https://gitlab.com",
        authorize_url: "/oauth/authorize",
        token_url: "/oauth/token",
        response_type: 'code',
      }

      option :auth_token_params, {
        grant_type: 'authorization_code',
      }
      
      option :redirect_url

      # When `true`, client_id and client_secret are returned in extra['raw_info'].
      option :extra_client_id_and_client_secret, false

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

      def build_access_token
        verifier = request.params["code"]
        # Override regular client when using setup: proc
        if env['omniauth.params']['client_id'] && env['omniauth.params']['client_secret'] && env['omniauth.params']['site']
          client = ::OAuth2::Client.new(
            env['omniauth.params']['client_id'],
            env['omniauth.params']['client_secret'],
            site: env['omniauth.params']['site'],
            authorize_url: options.client_options.authorize_url,
            token_url: options.client_options.token_url,
            connection_opts: { proxy: env['omniauth.strategy'].options.client_options.proxy },
          )
          client.auth_code.get_token(verifier, {:redirect_uri => callback_url}.merge(token_params.to_hash(:symbolize_keys => true)), deep_symbolize(options.auth_token_params))
        else
          super
        end
      end

      def raw_info
        @raw_info ||= begin
          user = access_token.get('api/v4/user').parsed
          options[:extra_client_id_and_client_secret] ? { client_id: smart_client_id, client_secret: smart_client_secret, user: user } : { user: user }
        end
      end

      def smart_client_id
        @smart_client_id ||= env['omniauth.params']['client_id'] || env['omniauth.strategy'].options.client_id
      end

      def smart_client_secret
        @smart_client_secret ||= env['omniauth.params']['client_secret'] || env['omniauth.strategy'].options.client_secret
      end

      def callback_url
        options.redirect_url || (full_host + callback_path)
      end
    end
  end
end

OmniAuth.config.add_camelization 'gitlab', 'GitLab'
