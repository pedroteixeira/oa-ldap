#require 'net/ldap'
require 'ldap'
require 'omniauth/core'


module OmniAuth
  module Strategies
    class LDAP
      include OmniAuth::Strategy

      def initialize(app, name, host, port, base, options = {})
        @options = options
        @base = base
        @uid_key = options[:identifier_key] || "uid"

        @auth = nil
        @host = host
        @port = port

        if options[:username] && options[:password]
          @auth = {:method => :simple,
            :username => options[:username],
            :password => options[:password]}
        end

        super(app, name)
      end

      def connect
      end


      def bind(username, password)
        filter = "(#{@uid_key}=#{username})"

        ldap = Net::LDAP.new(:host => @host, :port => @port, :auth => @auth)
        result = ldap.bind_as(:base => @base,
                              :filter => filter,
                              :password => password)
        if result
          result.first.inspect
        else
          false
        end
      end

      def bind_jruby(username, password)

        begin
          conn = ::LDAP::Conn.new(host=@host, port=@port)
          dn = "#{@uid_key}=#{username},#{@base}"
          
          result = false
          
          conn.bind(dn=dn, password=password, method=::LDAP::LDAP_AUTH_SIMPLE) do
            conn.search(dn, ::LDAP::LDAP_SCOPE_BASE, "(&(objectclass=person))",
                        ["name","email","displayName"]) do |entry|

              result = entry
            end          
          end
          
          result = result.inspect
          
          @user_info = entry_map result
          @user_info[@uid_key] = username        
          @ldap_user_info = result
          return result
          
        rescue
          false
        end
      end

      def request_phase
        return fail!(:missing_information) unless (request[:username] && request[:password])

        result = bind_jruby(request[:username], request[:password])
          
        if result
          @env['REQUEST_METHOD'] = 'GET'
          @env['PATH_INFO'] = "#{OmniAuth.config.path_prefix}/#{name}/callback"
          @env['omniauth.auth'] = auth_hash

          callback_phase
        else 
          fail!(:invalid_credentials)
        end
      end


      def auth_hash
        OmniAuth::Utils.deep_merge(super(), {
                                     'uid' => @user_info["uid"],
                                     'strategy' => self.class.to_s,
                                     'user_info' => @user_info,
                                     'extra' => @ldap_user_info
        })
      end


      def entry_map(entry)
        {             
          'name' => entry_attr(entry, :name) || entry_attr(entry, :displayName),
          'displayName' => entry_attr(entry, :displayName),
          'uid' =>  entry_attr(entry, :uid),
          'email' => entry_attr(entry, :mail) || entry_attr(entry, :email)
        }
      end

      def entry_attr(entry, key)
        key = key.to_s
        if entry[key]
          entry[key].first
        else
          nil
        end
      end

    end
  end
end
