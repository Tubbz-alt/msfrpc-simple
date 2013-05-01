module Msf
  module RPC
    module Simple
      module Features
        module Framework

          # Public: This module runs a db_nmap command
          #
          # range - an ipv4 ip address range in cidr format
          #
          # This method should only be run after running setup
          #
          # Returns nothing
          def nmap_range(range)

            # Call out to nmap to scan the given range
            `nmap --top-ports 100 -oX /tmp/metasploit_temp.xml #{range}`
            
            # Import the XML into metasploit
            _send_command("db_import /tmp/metasploit_temp.xml")
            
            # Wait for a few seconds while the xml is imported
            sleep 5        
          end

          # Public: This module runs a number of discovery modules. This method should only
          # be run after running setup, then the nmap_range method.
          #
          # host - an ipv4 ip address or hostname
          #
          # This method should only be run after running setup, and then the 
          # nmap_range method.
          #
          # Returns nothing

          def discover_range(range, threads=25)

            # Other Potential options
            #  - auxiliary/scanner/smb/pipe_auditor
            #  - auxiliary/scanner/smb/pipe_dcerpc_auditor
            #  - auxiliary/scanner/smb/smb_enumshares
            #  - auxiliary/scanner/smb/smb_enumusers
            modules_and_options = [
              {:module_name => "auxiliary/scanner/http/http_version", :module_options => {}},
              {:module_name => "auxiliary/scanner/http/cert", :module_options => {}},
              {:module_name => "auxiliary/scanner/ftp/ftp_version", :module_options => {}},
              {:module_name => "auxiliary/scanner/h323/h323_version", :module_options => {}},
              {:module_name => "auxiliary/scanner/imap/imap_version", :module_options => {}},
              {:module_name => "auxiliary/scanner/portscan/syn", :module_options => {}},
              {:module_name => "auxiliary/scanner/portscan/tcp", :module_options => {}},
              #{:module_name => "auxiliary/scanner/lotus/lotus_domino_version", :module_options => {}},
              {:module_name => "auxiliary/scanner/mysql/mysql_version", :module_options => {}},
              {:module_name => "auxiliary/scanner/netbios/nbname", :module_options => {}},
              {:module_name => "auxiliary/scanner/netbios/nbname_probe"},
              #{:module_name => "auxiliary/scanner/pcanywhere/pcanywhere_tcp", :module_options => {}},
              #{:module_name => "auxiliary/scanner/pcanywhere/pcanywhere_udp", :module_options => {}},
              {:module_name => "auxiliary/scanner/pop3/pop3_version", :module_options => {}},
              {:module_name => "auxiliary/scanner/postgres/postgres_version", :module_options => {}},
              {:module_name => "auxiliary/scanner/smb/smb_version", :module_options => {}},
              {:module_name => "auxiliary/scanner/snmp/snmp_enum", :module_options => {}},
              {:module_name => "auxiliary/scanner/ssh/ssh_version", :module_options => {}},
              {:module_name => "auxiliary/scanner/telnet/telnet_version", :module_options => {}},
              #{:module_name => "auxiliary/scanner/vmware/vmauthd_version", :module_options => {}}
            ]

            module_list.each do |mod|
              # Merge in default options
              mod[:options] = { 
                "RHOSTS" => "#{range}", 
                "THREADS" => "#{threads}"
              }

              # Module specific options
              mod[:options].merge!(mod[:module_options])

              # execute the module
               execute_module(mod)
            end
          end


          # Public: This module runs a number of bruteforce modules. This method should only
          # be run after running setup, then the nmap_range method.
          #
          # host - an ipv4 ip address or hostname
          #
          # This method should only be run after running setup, and then the 
          # nmap_range method.
          #
          # Returns nothing
          def bruteforce_range(range, user_file, pass_file, threads=25)

            module_list = [
              {:module_name => "auxiliary/scanner/http/http_login", :module_options => {}},
              {:module_name => "auxiliary/scanner/smb/smb_login", :module_options => {}},
              {:module_name => "auxiliary/scanner/snmp/snmp_login", :module_options => {}},
              {:module_name => "auxiliary/scanner/ssh/ssh_login", :module_options => {"SSH_TIMEOUT" => 3}}
            ]

            # Iterate through modules in the list, adding in generic and module-specific options
            # if they exist
            module_list.each do |mod|

              # Generic module options
              mod[:options] = { 
                "RHOSTS" => "#{range}",
                "USER_FILE" => "#{user_file}",
                "PASS_FILE" => "#{pass_file}",
                "THREADS" => "#{threads}"
              }
              # Module specific options
              mod[:options].merge!(mod[:module_options])

              execute_module(mod)
            end

          end

          # Public: This module runs a number of exploit modules. This method should only
          # be run after running setup, then the nmap_range method.
          #
          # host - an ipv4 ip address or hostname
          #
          # This method should only be run after running setup, and then the 
          # nmap_range method.
          #
          # Returns nothing
          def exploit_single(host)

            # TODO - will need to set up / manage a handler - should this go 
            # back to the console? 

            module_list = [
              { :module_name => "exploit/windows/smb/ms08_067_netapi", :module_options => {} }
            ]
            
            module_list.each do |mod|
              mod[:options] = { "RHOST" => "#{host}" }
              mod[:options].merge!(mod[:module_options])
              execute_module(mod)
            end
          end

          # Public: This method executes a specified metasploit module
          #
          # params - A parameters hash containing:
          #  - :module_name - a full metasploit module name
          #  - :options - a hash of options to be "set" for the module
          #
          # Note that typical behavior for metasploit when calling "module.execute" is to 
          # background the task. This method waits for the task to complete, thereby
          # allowing you to fire this method, then interact with the database to find
          # the requisite result(s).
          #
          # returns nothing
          def execute_module(params)
            module_name = params[:module_name]
            module_type = params[:module_name].split("/").first
            module_options = params[:options]
            raise "Error, bad module name" unless ["exploit", "auxiliary", "post", "encoder", "nop"].include? module_type
            
            # Execute the module and obtain the job details
            job_details = @client.call("module.execute", module_type, module_name, module_options)

            while @client.call("job.list").has_key?(job_details["job_id"].to_s)
              # Wait while the module is executed in the background
              sleep 1
            end

          end
=begin
          # Public: execute_module_and_return_output
          #
          # This method runs a module in a metasploit console and captures the output
          # to a string which is returned at the end of the module. An attempt is made
          # to remove the metasploit banner, which is simply noise
          # 
          # Note that this is currently deprecated, but preserved here in case a different
          # approach (text output needed) to running modules is req'd. Please use the 
          # execute_module method to run a module going forward. While output is not 
          # preserved when running that method, all appropriate results should be captured
          # in the database 
          # 
          # Returns a string with module output
          def execute_module_and_return_output(params)
            module_name = params[:module_name]
            module_option_string = params[:module_option_string]

            # split up the module name into type / name
            module_type = module_name.split("/").first
            raise "Error, bad module name" unless ["exploit", "auxiliary", "post", "encoder", "nop"].include? module_type

            # TODO - we may have to deal w/ targets somehow

            #info = @client.call("module.execute", module_type, module_name, module_options)
            #@client.call("job.info", info["job_id"])

            # The module output will be not available when run this way; to
            # capture the result of the print_* commands, you have to set the
            # output driver of the module to something you can read from (Buffer,
            # File, etc). For your use case, the best bet is to run the module
            # via the Console API instead of module.execute, and use that to read
            # the output from the console itself, which provides buffer output for you.
            output = ""

            # Create the console and get its id
            console = @client.call("console.create")
            console_id = console["id"]

            # Do an initial read / discard to pull out the banner
            @client.call("console.read", console_id)

            # Move to the context of our module
            @client.call("console.write", console_id, "use #{module_name}\n")

            # Set up the module's datastore
            module_option_string.split(",").each do |module_option|
              @client.call "console.write", console_id, "set #{module_option}\n"
              module_output = @client.call("console.read", console_id)
              output += "#{module_output['data']}"
            end

            # Ugh, this is horrible, but the read call is currently racey
            5.times do
              module_output = @client.call("console.read", console_id)
              output += "#{module_output['data']}"
            end

            # Depending on the module_type, kick off the module
            if module_type == "auxiliary"
              @client.call "console.write", console_id, "run\n"
            elsif module_type == "exploit"
              @client.call "console.write", console_id, "exploit\n"
            else
              return "Unsupported"
            end

            # do an initial read of the module's output
            module_output = @client.call("console.read", console_id)
            output += "#{module_output['data']}"

            until !module_output["busy"] do
              module_output = @client.call("console.read", console_id)
              output += "#{module_output['data']}"
              return "Module Error" if module_output["result"] == "failure"
            end

            # Ugh, this is horrible, but the read call is currently racey
            5.times do
              module_output = @client.call("console.read", console_id)
              output += "#{module_output['data']}"
            end

            # Clean up
            @client.call("console.destroy", console_id)

          output
          end
=end
        end
      end
    end
  end
end
