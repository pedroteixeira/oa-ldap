require 'net/ldap'
require 'omniauth/core'

module OmniAuth
  module Strategies
    class LDAP
      include OmniAuth::Strategy

      def initialize(app, name, host, port, base, options = {})
        @options = options
        @base = base
        @identifier_key = options[:identifier_key] || "uid"

        @ldap = Net::LDAP.new(:host => host, :port => port)        
        if options[:username] && options[:password]
          @ldap.auth options[:username], options[:password]
        end

        super(app, name)
      end


      def request_phase
        return fail!(:missing_information) unless (request[:identifier] && request[:password])
        

        result = @ldap.bind_as(:base => @base,
                               :filter => "(#{@identifier_key}=#{request[:identifier]})",
                               :password => request[:password])
        

        if result
          env['REQUEST_METHOD'] = 'GET'
          env['PATH_INFO'] = request.path + '/callback'
          request['auth'] = auth_hash(result.first)
          @app.call(env)
        else
          fail!(:invalid_credentials)
        end

      end


      def auth_hash(entry)
        OmniAuth::Utils.deep_merge(super(), {
          'uid' => (entry.send @identifier_key)[0],
          'strategy' => self.class.to_s,                                    
          'user_info' => {             
                                       'name' => entry_attr(entry, :name),
                                       'displayName' => entry_attr(entry, :displayName),
                                       'uid' =>  entry_attr(entry, :uid),
                                       'email' => entry_attr(entry, :mail) || entry_attr(entry, :email)
          }
        })
      end


      def callback_phase
        @app.call(env)
      end      

      def entry_attr(entry, key)
        (entry.attribute_names.member?(key) && entry.send(key) && (entry.send key)[0]) || nil
      end

    end
  end
end
