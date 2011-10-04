require 'sinatra/base'

module Sinatra
  module CasClient
    
    def self.registered(app)
      app.set :config, nil
      app.set :client, nil
      app.set :log, nil
      app.set :fake_user, nil
      app.set :fake_extra_attributes, nil        
    end
    
    def protect_with_cas(path) 
      before path do        
        raise "Cannot use the CASClient filter because it has not yet been configured." if options.config.nil?
        
        begin          
          if options.fake_user
            session[options.client.username_session_key] = options.fake_user
            session[:casfilteruser] = options.fake_user
            session[options.client.extra_attributes_session_key] = options.fake_extra_attributes if options.fake_extra_attributes
            return true
          end
          
          last_st = session[:cas_last_valid_ticket]
          last_st_service = session[:cas_last_valid_ticket_service]          
          halt 200, "CAS Single-Sign-Out request intercepted." if single_sign_out
          
          st = read_ticket
          if st && last_st && 
              last_st == st.ticket && 
              last_st_service == st.service
            # warn() rather than info() because we really shouldn't be re-validating the same ticket. 
            # The only situation where this is acceptable is if the user manually does a refresh and 
            # the same ticket happens to be in the URL.
            options.log.warn("Re-using previously validated ticket since the ticket id and service are the same.")
            return true
          elsif last_st &&
              !options.config[:authenticate_on_every_request] && 
              session[options.client.username_session_key]
            # Re-use the previous ticket if the user already has a local CAS session (i.e. if they were already
            # previously authenticated for this service). This is to prevent redirection to the CAS server on every
            # request.
            #
            # This behaviour can be disabled (so that every request is routed through the CAS server) by setting
            # the :authenticate_on_every_request config option to true. However, this is not desirable since
            # it will almost certainly break POST request, AJAX calls, etc.
            options.log.debug "Existing local CAS session detected for #{session[options.client.username_session_key].inspect}. "+
            "Previous ticket #{last_st.inspect} will be re-used."
            return true
          end
          
          if st
            options.client.validate_service_ticket(st) unless st.has_been_validated?
            
            if st.is_valid?
              #if is_new_session              
              options.log.info("Ticket #{st.ticket.inspect} for service #{st.service.inspect} belonging to user #{st.user.inspect} is VALID.")
              
              session[options.client.username_session_key] = st.user.dup
              session[options.client.extra_attributes_session_key] = HashWithIndifferentAccess.new(st.extra_attributes) if st.extra_attributes
              
              if st.extra_attributes
                options.log.debug("Extra user attributes provided along with ticket #{st.ticket.inspect}: #{st.extra_attributes.inspect}.")
              end
              
              # RubyCAS-Client 1.x used :casfilteruser as it's username session key,
              # so we need to set this here to ensure compatibility with configurations
              # built around the old client.
              session[:casfilteruser] = st.user
              
              if options.config[:enable_single_sign_out]
                options.client.ticket_store.store_service_session_lookup(st, controller)
              end
              #end
              
              # Store the ticket in the session to avoid re-validating the same service
              # ticket with the CAS server.
              session[:cas_last_valid_ticket] = st.ticket
              session[:cas_last_valid_ticket_service] = st.service
              
              if st.pgt_iou
                unless session[:cas_pgt] && session[:cas_pgt].ticket && session[:cas_pgt].iou == st.pgt_iou
                  options.log.info("Receipt has a proxy-granting ticket IOU. Attempting to retrieve the proxy-granting ticket...")
                  pgt = options.client.retrieve_proxy_granting_ticket(st.pgt_iou)
                  
                  if pgt
                    options.log.debug("Got PGT #{pgt.ticket.inspect} for PGT IOU #{pgt.iou.inspect}. This will be stored in the session.")
                    session[:cas_pgt] = pgt
                    # For backwards compatibility with RubyCAS-Client 1.x configurations...
                    session[:casfilterpgt] = pgt
                  else
                    options.log.error("Failed to retrieve a PGT for PGT IOU #{st.pgt_iou}!")
                  end
                else
                  options.log.info("PGT is present in session and PGT IOU #{st.pgt_iou} matches the saved PGT IOU.  Not retrieving new PGT.")
                end
              end
              return true
            else
              options.log.warn("Ticket #{st.ticket.inspect} failed validation -- #{st.failure_code}: #{st.failure_message}")
              unauthorized!(st)
              return false
            end
          else # no service ticket was present in the request
            if returning_from_gateway?
              options.log.info "Returning from CAS gateway without authentication."
              
              # unset, to allow for the next request to be authenticated if necessary
              session[:cas_sent_to_gateway] = false
              
              if use_gatewaying?
                options.log.info "This CAS client is configured to use gatewaying, so we will permit the user to continue without authentication."
                session[options.client.username_session_key] = nil
                return true
              else
                options.log.warn "The CAS client is NOT configured to allow gatewaying, yet this request was gatewayed. Something is not right!"
              end
            end
            
            unauthorized!
            return false
          end
        rescue OpenSSL::SSL::SSLError
          options.log.error("SSL Error: hostname was not match with the server certificate. You can try to disable the ssl verification with a :force_ssl_verification => false in your configurations file.")
          unauthorized!
          return false
        end
      end      
    end  
    
  end
  
  register CasClient
end
