require 'casclient'

module Sinatra
  module CasClientHelper
    
    def use_gatewaying?
      options.config[:use_gatewaying]
    end
    
    def login_to_service
      resp = options.client.login_to_service(credentials, return_path)
      if resp.is_failure?
        options.log.info("Validation failed for service #{return_path.inspect} reason: '#{resp.failure_message}'")
      else
        options.log.info("Ticket #{resp.ticket.inspect} for service #{return_path.inspect} is VALID.")
      end
      
      resp
    end
    
    def logout(service = nil)
      referer = service || request.referer
      st = session[:cas_last_valid_ticket]
      options.client.ticket_store.cleanup_service_session_lookup(st) if st
      # send(:reset_session)
			session.delete(:casfilteruser)
      send(:redirect, options.client.logout_url(referer))
    end
    
    def single_sign_out
      
      # Avoid calling raw_post (which may consume the post body) if
      # this seems to be a file upload
      if content_type = headers["CONTENT_TYPE"] &&
          content_type =~ %r{^multipart/}
        return false
      end
      
      if request.post? &&
          params['logoutRequest'] &&
          #This next line checks the logoutRequest value for both its regular and URI.escape'd form. I couldn't get
        #it to work without URI.escaping it from rubycas server's side, this way it will work either way.
        [params['logoutRequest'],URI.unescape(params['logoutRequest'])].find{|xml| xml =~
        %r{^<samlp:LogoutRequest.*?<samlp:SessionIndex>(.*)</samlp:SessionIndex>}m}
        # TODO: Maybe check that the request came from the registered CAS server? Although this might be
        #       pointless since it's easily spoofable...
        si = $~[1]
        
        unless options.config[:enable_single_sign_out]
          options.log.warn "Ignoring single-sign-out request for CAS session #{si.inspect} because ssout functionality is not enabled (see the :enable_single_sign_out config option)."
          return false
        end
        
        options.log.debug "Intercepted single-sign-out request for CAS session #{si.inspect}."
        
        options.client.ticket_store.process_single_sign_out(si)             
        
        # Return true to indicate that a single-sign-out request was detected
        # and that further processing of the request is unnecessary.
        return true
      end
      
      # This is not a single-sign-out request.
      return false
    end
    
    def read_ticket
      ticket = params[:ticket]
      return nil unless ticket
      
      options.log.debug("Request contains ticket #{ticket.inspect}.")
      
      if ticket =~ /^PT-/
        CASClient::ProxyTicket.new(ticket, options.config[:service_url], params[:renew])
      else
        CASClient::ServiceTicket.new(ticket, options.config[:service_url], params[:renew])
      end
    end
    
    def returning_from_gateway?
      session[:cas_sent_to_gateway]
    end
    
    def unauthorized!(vr = nil)
      if request.preferred_type == "text/html"
        redirect_to_cas_for_authentication
      else
        # if vr
          # case request.preferred_type
          # when "text/xml", "application/xml"
            # content_type :xml
            # vr.failure_message.to_xml(:root => 'errors')
          # when "text/json", "application/json"
            # { :errors => { :error => vr.failure_message }}.to_json
          # end
        # else
# 
        # end
        halt 401, "Unauthorised!"
      end
      
    end
    
    def redirect_to_cas_for_authentication
      redirect_url = options.client.add_service_to_login_url(options.config[:service_url])
      
      if use_gatewaying?
        session[:cas_sent_to_gateway] = true
        redirect_url << "&gateway=true"
      else
        session[:cas_sent_to_gateway] = false
      end
      
      if session[:previous_redirect_to_cas] &&
          session[:previous_redirect_to_cas] > (Time.now - 1.second)
        options.log.warn("Previous redirect to the CAS server was less than a second ago. The client at #{request.remote_ip.inspect} may be stuck in a redirection loop!")
        session[:cas_validation_retry_count] ||= 0
        
        if session[:cas_validation_retry_count] > 3
          options.log.error("Redirection loop intercepted. Client at #{request.remote_ip.inspect} will be redirected back to login page and forced to renew authentication.")
          redirect_url += "&renew=1&redirection_loop_intercepted=1"
        end
        
        session[:cas_validation_retry_count] += 1
      else
        session[:cas_validation_retry_count] = 0
      end
      session[:previous_redirect_to_cas] = Time.now
      
      options.log.debug("Redirecting to #{redirect_url.inspect}")
      redirect redirect_url
    end
    
    # End module
  end
  
  helpers CasClientHelper  
end
